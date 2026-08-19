import AppKit
import Combine
import Foundation
import Network

@MainActor
final class GuardianController: ObservableObject {
    static let shared = GuardianController()

    @Published private(set) var mode: GuardianMode = .off {
        didSet {
            guard oldValue != mode else { return }
            updateMonitoringActivityAssertion()
        }
    }
    @Published private(set) var baseline: IPObservation?
    @Published private(set) var current: IPObservation?
    @Published private(set) var protectedApps: [ProtectedApp] = []
    @Published private(set) var events: [EventRecord] = []
    @Published private(set) var policy: IPChangePolicy = .exactIP
    /// Saved, not draft. The picker edits its own copy and only reaches here
    /// when the user presses Save, so Protection never starts on a half-made
    /// choice.
    @Published private(set) var allowedCountries: [String] = []
    @Published private(set) var lastError: String?
    @Published private(set) var lastCheckAt: Date?
    private(set) var proxyState: SystemProxyState = .direct
    @Published private(set) var routeIdentity: NetworkRouteIdentity = .direct
    @Published private(set) var appsDisposition: ProtectedAppsDisposition = .notProtected
    @Published private(set) var nextRetryAt: Date?
    @Published private(set) var confirmationChecksCompleted = 0
    @Published private(set) var retryAttemptsCompleted = 0
    @Published private(set) var retryAttempt = 0
    @Published private(set) var isRetryCycleActive = false
    @Published private(set) var runningProtectedProcessCount = 0
    @Published private(set) var appRuntimeStates: [UUID: ProtectedAppsDisposition] = [:]
    @Published private(set) var isConnectionOverviewLoading = false
    @Published private(set) var connectionOverviewError: String?
    @Published private(set) var pausedProtectedProcessCount = 0
    /// Shown next to the application list for a few seconds. Choosing a file and
    /// watching nothing happen tells the user nothing, and the answer belongs
    /// where they are looking rather than in the status line above.
    @Published private(set) var applicationNotice: String?

    let checkInterval: TimeInterval = 3
    let retryDelay: TimeInterval = 2
    let overviewRefreshInterval: TimeInterval = 10
    let maximumRetryAttempts = 3
    let maximumActivityRecords = 200

    private struct VerificationRequest {
        let reason: String
        let strong: Bool
        let countsTowardRetryLimit: Bool
        let generation: Int
    }

    private let defaults = UserDefaults.standard
    private let processGuard = ProcessGuard.shared
    private let processQueue = DispatchQueue(
        label: "IPGuardian.ProcessGuard",
        qos: .userInitiated
    )
    private let pathMonitor = NWPathMonitor()
    private let pathQueue = DispatchQueue(label: "IPGuardian.NWPathMonitor")

    private let appsKey = "IPGuardian.protectedApps"
    // This key intentionally differs from its pre-release name, so a fresh
    // version 1 install always starts at Exact IP, whatever an earlier test
    // build left behind.
    private let policyKey = "IPGuardian.ipChangePolicySelection"
    private let allowedCountriesKey = "IPGuardian.allowedCountries"

    private var periodicTask: Task<Void, Never>?
    private var enforcementTask: Task<Void, Never>?
    private var proxyTask: Task<Void, Never>?
    private var interfaceTask: Task<Void, Never>?
    private var verificationTask: Task<Void, Never>?
    private var networkDebounceTask: Task<Void, Never>?
    private var retryTask: Task<Void, Never>?
    private var connectionOverviewTask: Task<Void, Never>?
    private var routeRefreshTask: Task<Void, Never>?
    private var runtimeRefreshTask: Task<Void, Never>?
    private var connectionOverviewGeneration = 0
    private var routeRefreshGeneration = 0
    private var pendingVerification: VerificationRequest?
    private var generation = 0
    private var receivedInitialPath = false
    private var lastPathFingerprint: String?
    private var lastInterfaceSnapshot: String?
    private var lastProxySignature: String?
    private var launchObserver: NSObjectProtocol?
    private var powerObservers: [NSObjectProtocol] = []
    private var activityToken: NSObjectProtocol?
    private var confirmationTracker = ChangeConfirmationTracker()
    private var retryFailureTracker = RetryFailureTracker(maximumRetries: 3)
    private var candidateObservation: IPObservation?
    private var isUnverifiedIncidentActive = false
    private var isShuttingDown = false
    private var awaitingManualCloseAfterRetryExhaustion = false
    private var lastOverviewRefreshRequestedAt: Date?
    private var nextProtectedCheckAt: Date?
    private var recoveryLoggedForCurrentIncident = false
    private var isStartingProtection = false
    private var isTurningOffProtection = false
    /// True only after IP Guardian itself closed the protected applications on
    /// a confirmed unsafe connection. `appsDisposition == .closed` cannot carry
    /// this: it is also true of the ordinary case where the user simply never
    /// opened them, which Protection requires before it can even start.
    private var closedApplicationsAwaitingReopen = false
    private var applicationNoticeTask: Task<Void, Never>?
    private let applicationNoticeDuration: TimeInterval = 7

    private init() {
        loadPreferences()
        proxyState = IPService.currentProxyState()
        routeIdentity = NetworkRouteReader.current(proxy: proxyState)
        lastProxySignature = proxyState.routeSignature

        NotificationService.requestAuthorization()

        startApplicationLaunchGuard()
        startPowerNotifications()
        startNetworkPathMonitor()
        startPeriodicLoop()
        startEnforcementLoop()
        startProxyLoop()
        startInterfaceLoop()

        // Protection is session-scoped. Every launch starts unprotected.
        baseline = nil
        mode = .off
        appsDisposition = .notProtected
        refreshRunningProtectedProcessCount()
        refreshConnectionOverview()
    }

    var isProtectionActive: Bool { mode != .off }
    var isPolicyLocked: Bool { isProtectionActive }
    var hasPausedProcesses: Bool { pausedProtectedProcessCount > 0 }
    var protectedCheckIntervalText: String {
        let seconds = Int(checkInterval)
        return "\(seconds) \(seconds == 1 ? "second" : "seconds")"
    }
    var hasRunningProtectedApps: Bool { runningProtectedProcessCount > 0 }
    var activeProtectedApplicationCount: Int {
        ProtectedAppTally.activeCount(states: protectedApps.map(runtimeState(for:)))
    }
    var requiresManualClose: Bool { awaitingManualCloseAfterRetryExhaustion }
    var manualCloseIsRetryExhaustion: Bool {
        requiresManualClose && retryAttemptsCompleted >= maximumRetryAttempts
    }
    var candidate: IPObservation? { candidateObservation }
    var canStartProtection: Bool {
        ProtectionReadiness.canStart(
            protectedAppCount: protectedApps.count,
            runningProcessCount: runningProtectedProcessCount,
            proxyConfigurationIncomplete: routeIdentity.proxyConfigurationIncomplete,
            needsAllowedCountries: policy == .sameCountry
                && !AllowedCountries.isComplete(allowedCountries)
        )
    }
    var currentRouteSummary: String { routeIdentity.userFacingSummary }
    var connectionPathSummary: String { routeIdentity.connectionPathSummary }
    var protectionStartRequirement: String? {
        ProtectionReadiness.requirement(
            protectedAppCount: protectedApps.count,
            runningProcessCount: runningProtectedProcessCount,
            proxyConfigurationIncomplete: routeIdentity.proxyConfigurationIncomplete,
            needsAllowedCountries: policy == .sameCountry
                && !AllowedCountries.isComplete(allowedCountries)
        )
    }

    var statusDetail: String {
        switch mode {
        case .off:
            if let lastError { return lastError }
            if isConnectionOverviewLoading, current == nil {
                return "Detecting the current IP, country and route. Protection is still off."
            }
            if current == nil, connectionOverviewError != nil {
                return "The current connection could not be detected. Retrying automatically while Protection remains off."
            }
            if let protectionStartRequirement { return protectionStartRequirement }
            return "Close protected apps, then start Protection to verify the current connection and create a trusted baseline."
        case .checking:
            if isRetryCycleActive {
                return "Retrying connection verification · Attempt \(max(1, retryAttempt)) of \(maximumRetryAttempts). Protected apps remain paused."
            }
            if baseline == nil {
                return "Verifying IPv4, country, route and IPv6 before Protection starts."
            }
            if confirmationChecksCompleted > 0 || candidateObservation != nil {
                return "A connection change was detected. Protected apps remain paused while the connection is verified."
            }
            return "Protected apps are paused while the connection is verified."
        case .protected:
            return "Protected apps are running on the trusted connection."
        case .unverified:
            return "The current connection could not be verified. Retrying · Attempt \(max(1, retryAttempt)) of \(maximumRetryAttempts) while apps remain paused."
        case .unsafe:
            if awaitingManualCloseAfterRetryExhaustion {
                if !manualCloseIsRetryExhaustion {
                    return "One or more protected processes could not be closed. They remain paused until Close Apps succeeds. Live connection monitoring continues."
                }
                return "Verification failed after \(maximumRetryAttempts) retries. Automatic retry stopped, protected apps remain paused and live connection monitoring continues."
            }
            return "The trusted connection changed. Protected apps were closed without being resumed. Live connection monitoring continues."
        }
    }

    var lastVerifiedSummary: String {
        guard let baseline else { return "No verified baseline" }
        switch policy {
        case .exactIP:
            return "\(countryDisplayName(baseline.countryLabel)) · \(baseline.ipv4)"
        case .sameCountry:
            return "\(allowedCountriesSummary) · rotating IP allowed"
        }
    }

    var allowedCountriesSummary: String {
        guard !allowedCountries.isEmpty else { return "No countries chosen" }
        return allowedCountries.map(countryDisplayName).joined(separator: ", ")
    }

    var changedFields: [String] {
        guard let baseline, let candidate = candidateObservation ?? current else { return [] }
        return ConnectionChangeSummary.changedFields(
            baseline: baseline,
            candidate: candidate,
            policy: policy
        )
    }

    func startProtection() async {
        guard mode == .off,
              !isStartingProtection,
              !isTurningOffProtection else { return }
        isStartingProtection = true
        defer { isStartingProtection = false }

        await refreshRunningProtectedProcessCountNow()
        let startRoute = await Task.detached(priority: .utility) {
            let proxy = IPService.currentProxyState()
            return (proxy, NetworkRouteReader.current(proxy: proxy))
        }.value
        guard mode == .off, !isTurningOffProtection else { return }
        proxyState = startRoute.0
        routeIdentity = startRoute.1
        if protectedApps.isEmpty {
            rejectProtectionStart("Add at least one application before starting Protection.")
            return
        }
        // Every other precondition is checked again here rather than trusted
        // from the button. Without this one, an empty list would mean no
        // country is permitted at all, and the apps would be closed seconds
        // after Protection reported itself active.
        if policy == .sameCountry, !AllowedCountries.isComplete(allowedCountries) {
            rejectProtectionStart("Choose up to \(AllowedCountries.maximumCount) allowed countries and save them before starting Protection.")
            return
        }
        if runningProtectedProcessCount > 0 {
            rejectProtectionStart("Close all protected applications before starting Protection.")
            return
        }
        if routeIdentity.proxyConfigurationIncomplete {
            rejectProtectionStart("The enabled Proxy configuration is incomplete. Fix its host, port or PAC URL before starting Protection.")
            return
        }
        cancelConnectionOverview()
        connectionOverviewError = nil
        generation += 1
        let startGeneration = generation
        baseline = nil
        candidateObservation = nil
        confirmationTracker.reset()
        confirmationChecksCompleted = 0
        resetRetryFailures()
        awaitingManualCloseAfterRetryExhaustion = false
        closedApplicationsAwaitingReopen = false
        lastError = nil
        nextRetryAt = nil
        refreshRunningProtectedProcessCount()
        appsDisposition = hasRunningProtectedApps ? .paused : .closed
        mode = .checking
        let apps = protectedApps
        let failsafeReady = await processOperation { $0.activateExitFailsafe() }
        guard generation == startGeneration, mode != .off else { return }
        guard failsafeReady else {
            mode = .off
            appsDisposition = .notProtected
            rejectProtectionStart("The process recovery helper could not be started. Protection remains off.")
            return
        }
        let pauseReport = await processOperation { $0.pause(apps) }
        guard generation == startGeneration, mode != .off else { return }
        guard pauseReport.succeeded else {
            _ = await processOperation { $0.resumeAll() }
            await processOperation { $0.deactivateExitFailsafe() }
            mode = .off
            appsDisposition = .notProtected
            rejectProtectionStart("A protected process could not be safely paused. Protection remains off.")
            return
        }
        await refreshRunningProtectedProcessCountNow()
        queueVerification(
            reason: "Initial protection verification",
            strong: true,
            pauseBeforeChecking: true,
            invalidateCurrent: false
        )
    }

    /// Returns false when running or paused protected processes must be closed
    /// before Protection can be turned off safely.
    ///
    /// On a verified connection the applications are simply left running: the
    /// user is ending a session, not escaping a dangerous one, and forcing
    /// them to lose unsaved work for that would be indefensible.
    @discardableResult
    func turnOffProtection() async -> Bool {
        guard !isTurningOffProtection else { return false }
        guard isProtectionActive else { return true }
        await refreshRunningProtectedProcessCountNow()
        if !ProtectionShutdown.mayLeaveApplicationsRunning(mode: mode),
           hasRunningProtectedApps || hasPausedProcesses {
            return false
        }
        _ = await finishTurningOff(closePausedApps: false)
        return true
    }

    func closeAppsAndTurnOffProtection() {
        guard !isTurningOffProtection else { return }
        Task { [weak self] in
            _ = await self?.finishTurningOff(closePausedApps: true)
        }
    }

    func closeProtectedApps() {
        guard !isTurningOffProtection else { return }
        Task { [weak self] in
            guard let self else { return }
            guard !self.isTurningOffProtection else { return }
            await self.refreshRunningProtectedProcessCountNow()
            guard !self.isTurningOffProtection else { return }
            // No notification here: the user pressed the button, confirmed it,
            // and is looking at the window that reports the result.
            _ = await self.finishTurningOff(closePausedApps: true)
        }
    }

    func retryAgain() {
        guard mode == .unsafe, manualCloseIsRetryExhaustion else { return }

        generation += 1
        let retryGeneration = generation
        pendingVerification = nil
        verificationTask?.cancel()
        verificationTask = nil
        networkDebounceTask?.cancel()
        retryTask?.cancel()
        cancelConnectionOverview()
        nextRetryAt = nil
        resetRetryFailures()
        awaitingManualCloseAfterRetryExhaustion = false
        lastError = nil
        isUnverifiedIncidentActive = true
        recoveryLoggedForCurrentIncident = false
        isRetryCycleActive = true
        retryAttempt = 1
        mode = .unverified
        let apps = protectedApps
        Task { [weak self] in
            guard let self else { return }
            guard self.generation == retryGeneration,
                  self.mode == .unverified else { return }
            let report = await self.processOperation { $0.pause(apps) }
            await self.refreshRunningProtectedProcessCountNow()
            guard self.generation == retryGeneration,
                  self.mode == .unverified else { return }
            guard report.succeeded else {
                self.enterUnsafeAfterProcessFailure(report, action: "pause protected apps")
                return
            }
            self.queueVerification(
                reason: "Manual retry",
                strong: true,
                pauseBeforeChecking: true,
                invalidateCurrent: false,
                countsTowardRetryLimit: true
            )
        }
    }

    func addApplication(at url: URL) {
        let standardized = url.standardizedFileURL
        guard standardized.pathExtension.lowercased() == "app" else {
            showApplicationNotice(
                "Only applications can be protected. Choose a program, such as a browser, from your Applications folder."
            )
            return
        }
        if let rejection = Self.unsupportedApplicationReason(for: standardized) {
            showApplicationNotice(rejection)
            log("WARN", rejection)
            NSSound.beep()
            return
        }
        let bundle = Bundle(url: standardized)
        let app = ProtectedApp(
            name: bundle?.object(forInfoDictionaryKey: "CFBundleDisplayName") as? String
                ?? bundle?.object(forInfoDictionaryKey: "CFBundleName") as? String
                ?? standardized.deletingPathExtension().lastPathComponent,
            bundleIdentifier: bundle?.bundleIdentifier,
            path: standardized.path
        )

        guard !protectedApps.contains(where: {
            ($0.bundleIdentifier != nil && $0.bundleIdentifier == app.bundleIdentifier)
                || URL(fileURLWithPath: $0.path).standardizedFileURL.path == standardized.path
        }) else {
            showApplicationNotice("\(app.name) is already protected.")
            return
        }

        protectedApps.append(app)
        persistApps()
        log("INFO", "Added protected app: \(app.name).")

        let currentMode = mode
        let actionGeneration = generation
        let apps = protectedApps
        let shouldPauseInUnsafe = awaitingManualCloseAfterRetryExhaustion
        if currentMode != .off {
            Task { [weak self] in
                guard let self else { return }
                guard self.generation == actionGeneration,
                      self.mode != .off,
                      !self.isTurningOffProtection else { return }
                let report = await self.processOperation { guardInstance in
                    switch currentMode {
                    case .checking, .unverified, .protected:
                        return guardInstance.pause(apps)
                    case .unsafe where shouldPauseInUnsafe:
                        return guardInstance.pause(apps)
                    case .unsafe:
                        return guardInstance.terminateNewMatches(apps)
                    case .off:
                        return ProcessActionReport(failedPIDs: [])
                    }
                }
                await self.refreshRunningProtectedProcessCountNow()
                guard self.generation == actionGeneration,
                      self.mode != .off,
                      !self.isTurningOffProtection else { return }
                guard report.succeeded else {
                    self.enterUnsafeAfterProcessFailure(report, action: "control the added protected app")
                    return
                }
                if currentMode == .protected, self.mode == .protected {
                    self.queueVerification(
                        reason: "Protected app added",
                        strong: true,
                        pauseBeforeChecking: true,
                        invalidateCurrent: true
                    )
                }
            }
        }
        refreshRunningProtectedProcessCount()
    }

    /// launchd keeps the pieces of the macOS interface alive, so closing one
    /// starts a close-and-relaunch loop that never settles. That is true of
    /// Finder, Dock and their neighbours in CoreServices; it is not true of
    /// ordinary bundled applications such as Calculator, which stay closed like
    /// any other app and are therefore allowed.
    ///
    /// IPGuardian is excluded for a different reason: its own recovery helper
    /// runs as a child process and would become a target of its own enforcement.
    nonisolated static func unsupportedApplicationReason(for url: URL) -> String? {
        let path = url.standardizedFileURL.path
        if path.hasPrefix("/System/Library/CoreServices/") {
            return "Finder, Dock and the rest of the macOS interface cannot be protected, because macOS restarts them immediately."
        }
        if path == Bundle.main.bundleURL.standardizedFileURL.path {
            return "IP Guardian cannot protect itself."
        }
        return nil
    }

    /// Replaces any notice still on screen and restarts the countdown, so a
    /// second rejected choice does not inherit the remains of the first one.
    private func showApplicationNotice(_ message: String) {
        applicationNotice = message
        applicationNoticeTask?.cancel()
        let duration = applicationNoticeDuration
        applicationNoticeTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(duration * 1_000_000_000))
            guard !Task.isCancelled, let self else { return }
            self.applicationNotice = nil
            self.applicationNoticeTask = nil
        }
    }

    func removeApplication(_ app: ProtectedApp) {
        guard mode == .off else {
            log("WARN", "Removing a protected app was refused while Protection was active.")
            return
        }
        protectedApps.removeAll { $0.id == app.id }
        persistApps()
        refreshRunningProtectedProcessCount()
        log("INFO", "Removed protected app: \(app.name).")
    }

    func updatePolicy(_ value: IPChangePolicy) {
        guard !isPolicyLocked else { return }
        policy = value
        defaults.set(value.rawValue, forKey: policyKey)
        // The list is kept across a switch. Exact IP ignores it, and losing a
        // saved choice for looking at the other policy would be a poor trade.
        log("INFO", "IP change policy set to \(value.title).")
        refreshConnectionOverview(force: true)
    }

    func updateAllowedCountries(_ codes: [String]) {
        guard !isPolicyLocked, policy == .sameCountry else { return }
        let normalized = AllowedCountries.normalized(codes)
        guard normalized != allowedCountries else { return }
        allowedCountries = normalized
        defaults.set(normalized, forKey: allowedCountriesKey)
        log(
            "INFO",
            normalized.isEmpty
                ? "Allowed countries were cleared."
                : "Allowed countries set to \(normalized.map(countryDisplayName).joined(separator: ", "))."
        )
        refreshConnectionOverview(force: true)
    }

    func clearEvents() {
        events.removeAll()
    }

    func runtimeState(for app: ProtectedApp) -> ProtectedAppsDisposition {
        appRuntimeStates[app.id] ?? (isProtectionActive ? .closed : .notProtected)
    }

    private func rejectProtectionStart(_ message: String) {
        lastError = message
        connectionOverviewError = message
        log("ERROR", "Protection start blocked: \(message)")
        NSSound.beep()
    }

    /// The power assertion suppresses App Nap and timer coalescing so protected
    /// checks keep their cadence. That cost is only justified while Protection
    /// is on; an idle Protection Off session must not hold it.
    private func updateMonitoringActivityAssertion() {
        if isProtectionActive {
            guard activityToken == nil else { return }
            activityToken = ProcessInfo.processInfo.beginActivity(
                options: [.userInitiatedAllowingIdleSystemSleep, .latencyCritical],
                reason: "IPGuardian connection monitoring"
            )
        } else if let activityToken {
            ProcessInfo.processInfo.endActivity(activityToken)
            self.activityToken = nil
        }
    }

    func prepareForTermination() {
        guard !isShuttingDown else { return }
        isShuttingDown = true

        periodicTask?.cancel()
        enforcementTask?.cancel()
        proxyTask?.cancel()
        interfaceTask?.cancel()
        verificationTask?.cancel()
        retryTask?.cancel()
        networkDebounceTask?.cancel()
        connectionOverviewTask?.cancel()
        routeRefreshTask?.cancel()
        runtimeRefreshTask?.cancel()
        pathMonitor.cancel()

        // Quitting IPGuardian cancels Protection, resumes anything we paused
        // and clears the in-memory trusted session.
        let resumeReport = processQueue.sync { processGuard.resumeAll() }
        baseline = nil
        candidateObservation = nil
        confirmationTracker.reset()
        confirmationChecksCompleted = 0
        resetRetryFailures()
        awaitingManualCloseAfterRetryExhaustion = false
        closedApplicationsAwaitingReopen = false
        lastError = nil
        nextRetryAt = nil
        nextProtectedCheckAt = nil
        isRetryCycleActive = false
        retryAttempt = 0
        events.removeAll()
        mode = .off
        appsDisposition = .notProtected
        if resumeReport.succeeded {
            processQueue.sync { processGuard.deactivateExitFailsafe() }
        }

        if let launchObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(launchObserver)
        }
        for observer in powerObservers {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        powerObservers.removeAll()
        if let activityToken {
            ProcessInfo.processInfo.endActivity(activityToken)
            self.activityToken = nil
        }
    }

    @discardableResult
    private func finishTurningOff(closePausedApps: Bool) async -> ProcessActionReport {
        guard !isTurningOffProtection else {
            return ProcessActionReport(failedPIDs: [])
        }
        isTurningOffProtection = true
        defer { isTurningOffProtection = false }
        generation += 1
        pendingVerification = nil
        verificationTask?.cancel()
        networkDebounceTask?.cancel()
        retryTask?.cancel()
        nextProtectedCheckAt = nil
        isRetryCycleActive = false
        retryAttempt = 0

        let actionReport: ProcessActionReport
        let apps = protectedApps
        if closePausedApps {
            actionReport = await processOperation { $0.terminateAll(apps) }
        } else {
            actionReport = await processOperation { $0.resumeAll() }
        }
        if !actionReport.succeeded {
            awaitingManualCloseAfterRetryExhaustion = true
            candidateObservation = nil
            mode = .unsafe
            appsDisposition = .paused
            let pids = actionReport.failedPIDs.sorted().map { String($0) }.joined(separator: ", ")
            lastError = closePausedApps
                ? "Could not close protected process IDs: \(pids). They remain paused; try Close Apps again."
                : "Could not resume protected process IDs: \(pids). Protection remains active; use Close Apps."
            log("ERROR", lastError ?? "A protected process could not be closed.")
            await refreshRunningProtectedProcessCountNow()
            refreshConnectionOverview(force: true)
            return actionReport
        }
        await processOperation { $0.deactivateExitFailsafe() }

        endUnverifiedIncident()
        confirmationTracker.reset()
        candidateObservation = nil
        confirmationChecksCompleted = 0
        resetRetryFailures()
        awaitingManualCloseAfterRetryExhaustion = false
        lastError = nil
        baseline = nil
        mode = .off
        appsDisposition = .notProtected
        await refreshRunningProtectedProcessCountNow()
        log(
            "INFO",
            closePausedApps
                ? "Protection turned off after paused apps were closed."
                : "Protection turned off."
        )
        refreshConnectionOverview(force: true)
        return actionReport
    }

    private func startPeriodicLoop() {
        periodicTask?.cancel()
        periodicTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 500_000_000)
                guard !Task.isCancelled, let self else { return }
                self.periodicTick()
            }
        }
    }

    private func periodicTick() {
        refreshRunningProtectedProcessCount()
        if mode == .off {
            refreshConnectionOverview()
            return
        }

        switch mode {
        case .protected:
            guard !isRetryCycleActive,
                  verificationTask == nil,
                  pendingVerification == nil else { return }
            if let nextProtectedCheckAt, Date() < nextProtectedCheckAt { return }
            queueVerification(
                reason: "Periodic connection check",
                strong: false,
                pauseBeforeChecking: false,
                invalidateCurrent: false
            )
        case .checking:
            guard !isRetryCycleActive,
                  candidateObservation != nil,
                  verificationTask == nil,
                  pendingVerification == nil else { return }
            if let nextProtectedCheckAt, Date() < nextProtectedCheckAt { return }
            queueVerification(
                reason: "Connection change confirmation",
                strong: true,
                pauseBeforeChecking: true,
                invalidateCurrent: false
            )
        case .unsafe:
            refreshConnectionOverview()
        case .unverified, .off:
            break
        }
    }

    private func startEnforcementLoop() {
        enforcementTask?.cancel()
        enforcementTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 250_000_000)
                guard !Task.isCancelled, let self else { return }
                let mode = self.mode
                guard !self.isTurningOffProtection,
                      mode == .checking || mode == .unverified || mode == .unsafe else {
                    continue
                }
                let apps = self.protectedApps
                let waitsForManualClose = self.awaitingManualCloseAfterRetryExhaustion
                let report = await self.processOperation { guardInstance in
                    switch mode {
                    case .checking, .unverified:
                        return guardInstance.pause(apps)
                    case .unsafe:
                        if waitsForManualClose {
                            return guardInstance.pause(apps)
                        } else {
                            return guardInstance.terminateNewMatches(apps)
                        }
                    case .off, .protected:
                        return ProcessActionReport(failedPIDs: [])
                    }
                }
                guard !Task.isCancelled else { return }
                guard !self.isTurningOffProtection else { continue }
                if !report.succeeded {
                    self.enterUnsafeAfterProcessFailure(report, action: "enforce the protected-app state")
                }
                self.refreshRunningProtectedProcessCount()
            }
        }
    }

    private func startProxyLoop() {
        proxyTask?.cancel()
        proxyTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 500_000_000)
                guard !Task.isCancelled, let self else { return }
                // Reading system proxy settings touches SystemConfiguration, so
                // it stays off the main actor even though it is inexpensive.
                let newState = await Task.detached(priority: .utility) {
                    IPService.currentProxyState()
                }.value
                guard !Task.isCancelled else { return }
                let previousSignature = self.lastProxySignature
                self.proxyState = newState
                self.lastProxySignature = newState.routeSignature

                guard let previousSignature,
                      previousSignature != newState.routeSignature else { continue }
                let newRoute = await Task.detached(priority: .utility) {
                    NetworkRouteReader.current(proxy: newState)
                }.value
                guard !Task.isCancelled else { return }
                self.routeIdentity = newRoute
                self.networkChanged(
                    reason: "Proxy route changed from \(previousSignature) to \(newState.routeSignature)"
                )
            }
        }
    }

    /// Safety net only. Reading the route identity runs `route` and `netstat`,
    /// so it is deliberately slow: `NWPathMonitor` already reports interface and
    /// default-route changes immediately, and every protected check re-reads the
    /// route anyway before comparing it with the trusted baseline.
    private func startInterfaceLoop() {
        interfaceTask?.cancel()
        interfaceTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                guard !Task.isCancelled, let self else { return }
                let newRoute = await Task.detached(priority: .utility) {
                    IPService.currentRouteIdentity()
                }.value
                let snapshot = newRoute.interfaceSignature
                guard !snapshot.isEmpty else { continue }
                if self.lastInterfaceSnapshot == nil {
                    self.lastInterfaceSnapshot = snapshot
                } else if self.lastInterfaceSnapshot != snapshot {
                    self.lastInterfaceSnapshot = snapshot
                    self.routeIdentity = newRoute
                    self.networkChanged(reason: "VPN or network interface changed")
                }
            }
        }
    }

    private func startNetworkPathMonitor() {
        pathMonitor.pathUpdateHandler = { [weak self] path in
            let fingerprint = Self.pathFingerprint(path)
            Task { @MainActor [weak self] in
                guard let self else { return }
                if !self.receivedInitialPath {
                    self.receivedInitialPath = true
                    self.lastPathFingerprint = fingerprint
                    return
                }
                guard self.lastPathFingerprint != fingerprint else { return }
                self.lastPathFingerprint = fingerprint
                self.networkChanged(
                    reason: path.status == .satisfied
                        ? "Network path changed"
                        : "Network connection is unavailable"
                )
            }
        }
        pathMonitor.start(queue: pathQueue)
    }

    private func networkChanged(reason: String) {
        guard !isTurningOffProtection else { return }
        refreshRouteIdentityForDisplay()
        guard isProtectionActive else {
            refreshConnectionOverview(force: true)
            return
        }

        guard mode != .unsafe else {
            refreshConnectionOverview(force: true)
            log("WARN", "A network change was detected while Unsafe; live connection monitoring was refreshed without changing the trusted baseline.")
            return
        }

        mode = .checking
        lastError = nil
        log("WARN", "A network change was detected; protected apps were paused and verification was queued.")

        generation += 1
        let networkGeneration = generation
        retryTask?.cancel()
        nextRetryAt = nil
        networkDebounceTask?.cancel()
        networkDebounceTask = Task { [weak self] in
            guard let self else { return }
            guard self.generation == networkGeneration,
                  !self.isTurningOffProtection else { return }
            let apps = self.protectedApps
            let report = await self.processOperation { $0.pause(apps) }
            await self.refreshRunningProtectedProcessCountNow()
            guard !Task.isCancelled else { return }
            guard self.generation == networkGeneration,
                  !self.isTurningOffProtection else { return }
            guard report.succeeded else {
                self.enterUnsafeAfterProcessFailure(report, action: "pause apps after a network change")
                return
            }
            try? await Task.sleep(nanoseconds: 200_000_000)
            guard !Task.isCancelled else { return }
            self.queueVerification(
                reason: reason,
                strong: true,
                pauseBeforeChecking: self.mode != .unsafe,
                invalidateCurrent: false
            )
        }
    }

    private func queueVerification(
        reason: String,
        strong: Bool,
        pauseBeforeChecking: Bool,
        invalidateCurrent: Bool,
        countsTowardRetryLimit: Bool = false
    ) {
        guard isProtectionActive, mode != .unsafe else { return }
        if invalidateCurrent { generation += 1 }

        if pauseBeforeChecking && mode != .unsafe {
            refreshRunningProtectedProcessCount()
            mode = .checking
        }

        let request = VerificationRequest(
            reason: reason,
            strong: strong,
            countsTowardRetryLimit: countsTowardRetryLimit,
            generation: generation
        )

        guard verificationTask == nil else {
            if pendingVerification == nil || strong {
                pendingVerification = request
            }
            return
        }
        beginVerification(request)
    }

    private func beginVerification(_ request: VerificationRequest) {
        if !request.strong {
            // The three-second cadence is measured from the start of the check.
            // Slow checks never overlap; when one takes longer than three seconds,
            // the next check starts as soon as the current one finishes.
            nextProtectedCheckAt = Date().addingTimeInterval(checkInterval)
        }

        verificationTask = Task { [weak self] in
            guard let self else { return }
            let knownObservation = self.baseline ?? self.current
            do {
                let observation = try await IPService.fetchProtectionObservation(
                    policy: self.policy,
                    allowedCountries: self.allowedCountries,
                    knownIPv4: knownObservation?.ipv4,
                    knownCountry: knownObservation?.countryLabel
                )
                guard !Task.isCancelled else {
                    self.finishVerificationCycle()
                    return
                }
                if request.generation == self.generation {
                    await self.handleSuccessfulVerification(observation)
                }
            } catch {
                guard !Task.isCancelled else {
                    self.finishVerificationCycle()
                    return
                }
                if request.generation == self.generation {
                    await self.handleVerificationFailure(error, request: request)
                }
            }
            self.finishVerificationCycle()
        }
    }

    private func finishVerificationCycle() {
        verificationTask = nil
        guard let next = pendingVerification else {
            if mode == .checking,
               !isRetryCycleActive,
               candidateObservation != nil {
                nextProtectedCheckAt = Date().addingTimeInterval(checkInterval)
            }
            return
        }
        pendingVerification = nil
        guard mode != .unsafe,
              next.generation == generation,
              isProtectionActive else { return }
        beginVerification(next)
    }

    private func handleSuccessfulVerification(
        _ observation: IPObservation
    ) async {
        let handlingGeneration = generation
        if mode == .unsafe {
            // A request queued before Unsafe may still finish. Its observation
            // may update the live display, but it must never unlock Unsafe,
            // replace the baseline, or resume protected applications.
            applyCurrentObservation(observation)
            return
        }
        resetRetryFailures()
        awaitingManualCloseAfterRetryExhaustion = false
        applyCurrentObservation(observation)

        guard let baseline else {
            // Trusting this connection would mean reporting Protected and then
            // closing the applications a few seconds later, when the very same
            // country fails the rule that was already known at Start. Refuse
            // now and say why.
            if policy == .sameCountry,
               !AllowedCountries.allows(observation.countryLabel, in: allowedCountries) {
                await refuseStartOutsideAllowedCountries(observation)
                return
            }
            await establishBaseline(observation)
            return
        }

        switch SecurityDecision.evaluate(
            baseline: baseline,
            current: observation,
            policy: policy,
            allowedCountries: allowedCountries
        ) {
        case .safe:
            await restoreProtectedState()

        case .unsafe(let reasons):
            endUnverifiedIncident()
            let apps = protectedApps
            let pauseReport = await processOperation { $0.pause(apps) }
            await refreshRunningProtectedProcessCountNow()
            guard generation == handlingGeneration,
                  isProtectionActive,
                  !isTurningOffProtection else { return }
            guard pauseReport.succeeded else {
                enterUnsafeAfterProcessFailure(pauseReport, action: "pause apps for change confirmation")
                return
            }

            let newFingerprint = ChangeCandidateFingerprint(observation, policy: policy)
            let contradictedPreviousCandidate = confirmationTracker.fingerprint != nil
                && confirmationTracker.fingerprint != newFingerprint
            let confirmed = confirmationTracker.register(observation, policy: policy)
            confirmationChecksCompleted = confirmationTracker.completedConfirmationChecks
            candidateObservation = observation

            if contradictedPreviousCandidate {
                enterUnverified(
                    reason: "Confirmation checks returned different connection details."
                )
                return
            }

            if confirmed {
                let closeReport = await processOperation { $0.terminateAll(apps) }
                await refreshRunningProtectedProcessCountNow()
                guard generation == handlingGeneration,
                      isProtectionActive,
                      !isTurningOffProtection else { return }
                mode = .unsafe
                candidateObservation = nil
                if closeReport.succeeded {
                    appsDisposition = .closed
                    closedApplicationsAwaitingReopen = true
                    awaitingManualCloseAfterRetryExhaustion = false
                    lastError = reasons.joined(separator: " ")
                } else {
                    appsDisposition = .paused
                    awaitingManualCloseAfterRetryExhaustion = true
                    let pids = closeReport.failedPIDs.sorted().map { String($0) }.joined(separator: ", ")
                    lastError = reasons.joined(separator: " ")
                        + " Process IDs \(pids) could not be closed and remain paused."
                }
                nextRetryAt = nil
                confirmationChecksCompleted = 2
                log(
                    "CRITICAL",
                    "Unsafe connection confirmed; protected apps were closed or kept paused."
                )
                NotificationService.send(
                    title: "Unsafe connection confirmed",
                    body: closeReport.succeeded
                        ? "Protected apps were closed without being resumed."
                        : "Some protected processes remain paused and require Close Apps."
                )
                NSSound.beep()
                refreshConnectionOverview(force: true)
            } else {
                mode = .checking
                lastError = nil
                if confirmationChecksCompleted == 0 {
                    log(
                        "WARN",
                        "A suspicious connection was detected; protected apps remain paused while verification continues."
                    )
                }
            }
        }
    }

    private func handleVerificationFailure(_ error: Error, request: VerificationRequest) async {
        let handlingGeneration = generation
        let userMessage = (error as? IPServiceError)?.userFacingDescription
            ?? "Connection verification is temporarily unavailable."
        debugVerificationFailure(error, source: request.reason)

        if mode == .unsafe {
            log("ERROR", "The connection could not be verified for recovery.")
            return
        }

        let apps = protectedApps
        let pauseReport = await processOperation { $0.pause(apps) }
        await refreshRunningProtectedProcessCountNow()
        guard generation == handlingGeneration,
              isProtectionActive,
              !isTurningOffProtection else { return }
        guard pauseReport.succeeded else {
            enterUnsafeAfterProcessFailure(pauseReport, action: "pause apps after a verification failure")
            return
        }
        if request.countsTowardRetryLimit {
            let exhausted = retryFailureTracker.recordFailedRetry()
            retryAttemptsCompleted = retryFailureTracker.completedRetries
            if exhausted {
                log("ERROR", userMessage)
                enterUnsafeAfterRetryExhaustion(reason: userMessage)
                return
            }
        }
        enterUnverified(reason: userMessage)
    }

    /// Ends the start attempt cleanly: nothing was trusted, so nothing is kept
    /// and any process paused for the attempt is released.
    private func refuseStartOutsideAllowedCountries(_ observation: IPObservation) async {
        generation += 1
        pendingVerification = nil
        let country = countryDisplayName(observation.countryLabel)

        _ = await processOperation { $0.resumeAll() }
        await processOperation { $0.deactivateExitFailsafe() }

        baseline = nil
        candidateObservation = nil
        confirmationTracker.reset()
        confirmationChecksCompleted = 0
        resetRetryFailures()
        awaitingManualCloseAfterRetryExhaustion = false
        closedApplicationsAwaitingReopen = false
        nextRetryAt = nil
        nextProtectedCheckAt = nil
        endUnverifiedIncident()
        mode = .off
        appsDisposition = .notProtected
        await refreshRunningProtectedProcessCountNow()

        rejectProtectionStart(
            "The connection is in \(country), which is not one of your allowed countries. Protection did not start."
        )
        refreshConnectionOverview(force: true)
    }

    private func establishBaseline(_ observation: IPObservation) async {
        let handlingGeneration = generation
        let recoveredFromIncident = isUnverifiedIncidentActive
        baseline = observation
        confirmationTracker.reset()
        candidateObservation = nil
        confirmationChecksCompleted = 0
        resetRetryFailures()
        awaitingManualCloseAfterRetryExhaustion = false
        lastError = nil
        nextRetryAt = nil
        endUnverifiedIncident()
        mode = .protected
        nextProtectedCheckAt = Date().addingTimeInterval(checkInterval)

        if appsDisposition != .closed {
            let report = await processOperation { $0.resumeAll() }
            await refreshRunningProtectedProcessCountNow()
            guard generation == handlingGeneration,
                  isProtectionActive,
                  !isTurningOffProtection else { return }
            guard report.succeeded else {
                enterUnsafeAfterProcessFailure(report, action: "resume apps after baseline verification")
                return
            }
        }
        if recoveredFromIncident {
            recoveryLoggedForCurrentIncident = true
        }
        log(
            "INFO",
            recoveredFromIncident
                ? "The connection was verified on retry; Protection is now active."
                : "Protection enabled with \(policy.title)."
        )
        NotificationService.send(
            title: "Connection verified",
            body: "IP Guardian Protection is active."
        )
    }

    private func restoreProtectedState() async {
        let handlingGeneration = generation
        let previousMode = mode
        let recoveredFromIncident = isUnverifiedIncidentActive
        confirmationTracker.reset()
        candidateObservation = nil
        confirmationChecksCompleted = 0
        resetRetryFailures()
        awaitingManualCloseAfterRetryExhaustion = false
        lastError = nil
        nextRetryAt = nil
        endUnverifiedIncident()
        mode = .protected
        nextProtectedCheckAt = Date().addingTimeInterval(checkInterval)

        if appsDisposition != .closed {
            let report = await processOperation { $0.resumeAll() }
            await refreshRunningProtectedProcessCountNow()
            guard generation == handlingGeneration,
                  isProtectionActive,
                  !isTurningOffProtection else { return }
            guard report.succeeded else {
                enterUnsafeAfterProcessFailure(report, action: "resume apps after connection verification")
                return
            }
        }

        if previousMode != .protected {
            if !recoveredFromIncident || !recoveryLoggedForCurrentIncident {
                log(
                    "INFO",
                    "The trusted connection was verified again; paused apps were resumed automatically."
                )
                if recoveredFromIncident {
                    recoveryLoggedForCurrentIncident = true
                }
            }
            // Worth interrupting for only when it leaves the user something to
            // do. Apps that were closed can be opened again; a pause and resume
            // around a network hiccup is routine and already visible in the
            // menu bar, and announcing it every time turns the notification
            // into noise on an unstable connection.
            if closedApplicationsAwaitingReopen {
                closedApplicationsAwaitingReopen = false
                NotificationService.send(
                    title: "Trusted connection restored",
                    body: "Protection is active; the apps that were closed may be opened again."
                )
            }
        }
    }

    private func enterUnverified(reason: String) {
        let isNewIncident = !isUnverifiedIncidentActive
        if isNewIncident {
            isUnverifiedIncidentActive = true
            recoveryLoggedForCurrentIncident = false
            resetRetryFailures()
        }
        mode = .unverified
        lastError = reason
        isRetryCycleActive = true
        log("ERROR", reason)
        scheduleAutomaticRetry()
    }

    private func scheduleAutomaticRetry() {
        retryTask?.cancel()
        guard mode == .unverified,
              retryAttemptsCompleted < maximumRetryAttempts else {
            nextRetryAt = nil
            return
        }

        let retryGeneration = generation
        isRetryCycleActive = true
        retryAttempt = min(retryAttemptsCompleted + 1, maximumRetryAttempts)
        nextRetryAt = Date().addingTimeInterval(retryDelay)
        let delayNanoseconds = UInt64(retryDelay * 1_000_000_000)
        retryTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: delayNanoseconds)
            guard !Task.isCancelled, let self,
                  self.mode == .unverified,
                  self.generation == retryGeneration else { return }
            self.nextRetryAt = nil
            self.queueVerification(
                reason: "Automatic retry",
                strong: true,
                pauseBeforeChecking: true,
                invalidateCurrent: false,
                countsTowardRetryLimit: true
            )
        }
    }

    private func enterUnsafeAfterRetryExhaustion(reason: String) {
        retryTask?.cancel()
        retryTask = nil
        nextRetryAt = nil
        isRetryCycleActive = false
        retryAttempt = maximumRetryAttempts
        log(
            "CRITICAL",
            "Connection verification failed after \(maximumRetryAttempts) automatic retries; protected apps remain paused."
        )
        endUnverifiedIncident()
        awaitingManualCloseAfterRetryExhaustion = true
        candidateObservation = nil
        mode = .unsafe
        lastError = "\(reason) Verification failed after \(maximumRetryAttempts) automatic retries."
        refreshRunningProtectedProcessCount()
        appsDisposition = hasRunningProtectedApps ? .paused : .closed
        NotificationService.send(
            title: "Connection verification failed",
            body: "Automatic retry stopped after \(maximumRetryAttempts) attempts. Protected apps remain paused."
        )
        NSSound.beep()
        refreshConnectionOverview(force: true)
    }

    private func enterUnsafeAfterProcessFailure(
        _ report: ProcessActionReport,
        action: String
    ) {
        let wasAlreadyWaitingForProcessRecovery = mode == .unsafe
            && awaitingManualCloseAfterRetryExhaustion
        retryTask?.cancel()
        retryTask = nil
        nextRetryAt = nil
        isRetryCycleActive = false
        awaitingManualCloseAfterRetryExhaustion = true
        candidateObservation = nil
        mode = .unsafe
        let pids = report.failedPIDs.sorted().map { String($0) }.joined(separator: ", ")
        lastError = pids.isEmpty
            ? "IP Guardian could not safely \(action)."
            : "IP Guardian could not safely \(action) for process IDs: \(pids)."
        log("CRITICAL", lastError ?? "A protected-process action failed.")
        guard !wasAlreadyWaitingForProcessRecovery else { return }
        NotificationService.send(
            title: "Protected process action failed",
            body: "Automatic recovery stopped. Live connection monitoring continues; use Close Apps or turn Protection off."
        )
        NSSound.beep()
        refreshConnectionOverview(force: true)
    }

    private func resetRetryFailures() {
        retryFailureTracker.reset()
        retryAttemptsCompleted = 0
        retryAttempt = 0
        isRetryCycleActive = false
        retryTask?.cancel()
        retryTask = nil
    }

    private func endUnverifiedIncident() {
        isUnverifiedIncidentActive = false
        isRetryCycleActive = false
        retryTask?.cancel()
        retryTask = nil
    }

    private func applyCurrentObservation(_ observation: IPObservation) {
        current = observation
        lastCheckAt = observation.checkedAt
    }

    /// Updates live connection information while Protection is off or Unsafe.
    /// In Unsafe this is observation-only: it never evaluates trust, replaces
    /// the baseline, resumes apps, or clears the Unsafe state.
    private func refreshConnectionOverview(force: Bool = false) {
        let requestedMode = mode
        guard requestedMode == .off || requestedMode == .unsafe else { return }
        let refreshInterval = requestedMode == .unsafe
            ? checkInterval
            : overviewRefreshInterval
        if force {
            cancelConnectionOverview()
        } else if let lastOverviewRefreshRequestedAt,
                  Date().timeIntervalSince(lastOverviewRefreshRequestedAt)
                    < refreshInterval {
            return
        }

        guard connectionOverviewTask == nil else { return }

        lastOverviewRefreshRequestedAt = Date()
        connectionOverviewGeneration += 1
        let requestGeneration = connectionOverviewGeneration
        isConnectionOverviewLoading = true

        connectionOverviewTask = Task { [weak self] in
            guard let self else { return }
            let overviewRoute = await Task.detached(priority: .utility) {
                let proxy = IPService.currentProxyState()
                return (proxy, NetworkRouteReader.current(proxy: proxy))
            }.value
            guard !Task.isCancelled,
                  self.mode == requestedMode,
                  requestGeneration == self.connectionOverviewGeneration else {
                self.finishConnectionOverview(generation: requestGeneration)
                return
            }
            self.proxyState = overviewRoute.0
            self.routeIdentity = overviewRoute.1
            self.lastProxySignature = overviewRoute.0.routeSignature
            do {
                let observation = try await IPService.fetchOverview(
                    policy: self.policy,
                    allowedCountries: self.allowedCountries
                )
                guard !Task.isCancelled,
                      self.mode == requestedMode,
                      requestGeneration == self.connectionOverviewGeneration else {
                    self.finishConnectionOverview(generation: requestGeneration)
                    return
                }
                self.applyCurrentObservation(observation)
                self.connectionOverviewError = nil
            } catch {
                guard !Task.isCancelled,
                      self.mode == requestedMode,
                      requestGeneration == self.connectionOverviewGeneration else {
                    self.finishConnectionOverview(generation: requestGeneration)
                    return
                }
                if requestedMode == .off {
                    self.current = nil
                }
                self.debugVerificationFailure(error, source: "Connection overview")
                let userMessage = (error as? IPServiceError)?.userFacingDescription
                    ?? "Connection verification is temporarily unavailable."
                self.connectionOverviewError = userMessage
                if requestedMode == .off {
                    self.lastCheckAt = Date()
                }
            }
            self.finishConnectionOverview(generation: requestGeneration)
        }
    }

    private func cancelConnectionOverview() {
        connectionOverviewGeneration += 1
        connectionOverviewTask?.cancel()
        connectionOverviewTask = nil
        isConnectionOverviewLoading = false
    }

    private func finishConnectionOverview(generation: Int) {
        guard generation == connectionOverviewGeneration else { return }
        isConnectionOverviewLoading = false
        connectionOverviewTask = nil
    }

    /// Route presentation is refreshed independently from the protection state
    /// so Wi-Fi, Ethernet, VPN and Proxy changes never leave stale UI in Unsafe.
    private func refreshRouteIdentityForDisplay() {
        routeRefreshGeneration += 1
        let requestGeneration = routeRefreshGeneration
        routeRefreshTask?.cancel()
        routeRefreshTask = Task { [weak self] in
            guard let self else { return }
            let routeState = await Task.detached(priority: .utility) {
                let proxy = IPService.currentProxyState()
                return (proxy, NetworkRouteReader.current(proxy: proxy))
            }.value
            guard !Task.isCancelled,
                  requestGeneration == self.routeRefreshGeneration else { return }
            self.proxyState = routeState.0
            self.routeIdentity = routeState.1
            self.lastProxySignature = routeState.0.routeSignature
            self.lastInterfaceSnapshot = routeState.1.interfaceSignature
            self.routeRefreshTask = nil
        }
    }

    private func processOperation<T: Sendable>(
        _ operation: @escaping @Sendable (ProcessGuard) -> T
    ) async -> T {
        let guardInstance = processGuard
        let queue = processQueue
        return await withCheckedContinuation { continuation in
            queue.async {
                continuation.resume(returning: operation(guardInstance))
            }
        }
    }

    private func runtimeSnapshot() async -> ProcessRuntimeSnapshot {
        let apps = protectedApps
        let active = isProtectionActive
        return await processOperation {
            $0.runtimeSnapshot(for: apps, protectionActive: active)
        }
    }

    private func applyRuntimeSnapshot(_ snapshot: ProcessRuntimeSnapshot) {
        runningProtectedProcessCount = snapshot.runningProcessCount
        pausedProtectedProcessCount = snapshot.pausedProcessCount
        appRuntimeStates = snapshot.states

        guard isProtectionActive else {
            appsDisposition = .notProtected
            return
        }
        let states = Array(snapshot.states.values)
        if states.contains(.running) {
            appsDisposition = .running
        } else if states.contains(.paused) {
            appsDisposition = .paused
        } else {
            appsDisposition = .closed
        }
    }

    private func refreshRunningProtectedProcessCount() {
        guard runtimeRefreshTask == nil else { return }
        runtimeRefreshTask = Task { [weak self] in
            guard let self else { return }
            let snapshot = await self.runtimeSnapshot()
            guard !Task.isCancelled else { return }
            self.applyRuntimeSnapshot(snapshot)
            self.runtimeRefreshTask = nil
        }
    }

    private func refreshRunningProtectedProcessCountNow() async {
        runtimeRefreshTask?.cancel()
        runtimeRefreshTask = nil
        applyRuntimeSnapshot(await runtimeSnapshot())
    }

    private func startApplicationLaunchGuard() {
        launchObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let application = notification.userInfo?[NSWorkspace.applicationUserInfoKey]
                    as? NSRunningApplication else { return }
            let bundleIdentifier = application.bundleIdentifier
            let bundlePath = application.bundleURL?.standardizedFileURL.path
            Task { @MainActor [weak self] in
                await self?.handleProtectedApplicationLaunch(
                    bundleIdentifier: bundleIdentifier,
                    bundlePath: bundlePath
                )
            }
        }
    }

    private func startPowerNotifications() {
        let center = NSWorkspace.shared.notificationCenter
        powerObservers.append(center.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in self?.handleWillSleep() }
        })
        powerObservers.append(center.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in self?.handleDidWake() }
        })
    }

    private func handleWillSleep() {
        guard isProtectionActive,
              mode != .unsafe,
              !isTurningOffProtection else { return }
        generation += 1
        pendingVerification = nil
        verificationTask?.cancel()
        verificationTask = nil
        retryTask?.cancel()
        nextRetryAt = nil
        let apps = protectedApps
        let report = processQueue.sync { processGuard.pause(apps) }
        if !report.succeeded {
            enterUnsafeAfterProcessFailure(report, action: "pause apps before sleep")
            return
        }
        refreshRunningProtectedProcessCount()
        mode = .checking
        lastError = "Mac entered sleep. Protected apps remain paused until the connection is verified after wake."
        log("WARN", "Mac is sleeping; running protected apps were paused and active checks were cancelled.")
    }

    private func handleDidWake() {
        guard isProtectionActive else {
            refreshConnectionOverview(force: true)
            return
        }
        guard mode != .unsafe else {
            refreshRouteIdentityForDisplay()
            refreshConnectionOverview(force: true)
            log("INFO", "Mac woke while Unsafe; live connection monitoring resumed without changing the trusted baseline.")
            return
        }
        networkChanged(reason: "Mac woke from sleep")
    }

    private func handleProtectedApplicationLaunch(
        bundleIdentifier: String?,
        bundlePath: String?
    ) async {
        guard !isTurningOffProtection else { return }
        let launchGeneration = generation
        guard processGuard.isProtectedApplication(
            bundleIdentifier: bundleIdentifier,
            bundlePath: bundlePath,
            protectedApps: protectedApps
        ) else { return }

        switch mode {
        case .off:
            break
        case .protected:
            let apps = protectedApps
            let report = await processOperation { $0.pause(apps) }
            await refreshRunningProtectedProcessCountNow()
            guard generation == launchGeneration,
                  isProtectionActive,
                  !isTurningOffProtection else { return }
            guard report.succeeded else {
                enterUnsafeAfterProcessFailure(report, action: "pause a newly launched protected app")
                return
            }
            queueVerification(
                reason: "Protected app launch verification",
                strong: true,
                pauseBeforeChecking: true,
                invalidateCurrent: true
            )
        case .checking, .unverified:
            let apps = protectedApps
            let report = await processOperation { $0.pause(apps) }
            await refreshRunningProtectedProcessCountNow()
            guard generation == launchGeneration,
                  isProtectionActive,
                  !isTurningOffProtection else { return }
            guard report.succeeded else {
                enterUnsafeAfterProcessFailure(report, action: "pause a newly launched protected app")
                return
            }
            log("WARN", "A protected app launched while the connection was not verified and was paused immediately.")
        case .unsafe:
            let apps = protectedApps
            let report: ProcessActionReport
            if awaitingManualCloseAfterRetryExhaustion {
                report = await processOperation { $0.pause(apps) }
                log("WARN", "A protected app launched after retry exhaustion and was paused immediately.")
            } else {
                report = await processOperation { $0.terminateNewMatches(apps) }
                log("CRITICAL", "A protected app launch was closed while the connection was unsafe.")
            }
            await refreshRunningProtectedProcessCountNow()
            guard generation == launchGeneration,
                  isProtectionActive,
                  !isTurningOffProtection else { return }
            if !report.succeeded {
                enterUnsafeAfterProcessFailure(report, action: "control a protected app launched while unsafe")
            }
        }
    }

    private func loadPreferences() {
        if let data = defaults.data(forKey: appsKey),
           let decoded = try? JSONDecoder().decode([ProtectedApp].self, from: data) {
            // A selection stored by an earlier version can name an application
            // this one refuses to protect. The rule has to apply on the way in
            // as well, or it is bypassed by simply having chosen the app before
            // the rule existed.
            protectedApps = decoded.filter {
                Self.unsupportedApplicationReason(for: URL(fileURLWithPath: $0.path)) == nil
            }
            if protectedApps.count != decoded.count { persistApps() }
        }

        if let rawPolicy = defaults.string(forKey: policyKey),
           let decoded = IPChangePolicy(rawValue: rawPolicy) {
            policy = decoded
        }
        if let stored = defaults.stringArray(forKey: allowedCountriesKey) {
            allowedCountries = AllowedCountries.normalized(stored)
        }
    }

    private func persistApps() {
        if let data = try? JSONEncoder().encode(protectedApps) {
            defaults.set(data, forKey: appsKey)
        }
    }

    private func log(_ level: String, _ message: String) {
        events = ActivityRecordPolicy.adding(
            level: level,
            message: message,
            to: events,
            maximumRecords: maximumActivityRecords
        )
    }

    private func debugVerificationFailure(_ error: Error, source: String) {
#if DEBUG
        let detail = (error as? LocalizedError)?.errorDescription
            ?? error.localizedDescription
        print("[IPGuardian][\(source)] \(detail)")
#endif
    }

    private func countryDisplayName(_ code: String?) -> String {
        guard let code = CountryCode.normalized(code) else { return "Unknown" }
        return Locale.current.localizedString(forRegionCode: code) ?? code
    }

    nonisolated private static func pathFingerprint(_ path: NWPath) -> String {
        let types: [(NWInterface.InterfaceType, String)] = [
            (.wifi, "wifi"),
            (.wiredEthernet, "ethernet"),
            (.cellular, "cellular"),
            (.loopback, "loopback"),
            (.other, "other")
        ]
        let active = types
            .compactMap { path.usesInterfaceType($0.0) ? $0.1 : nil }
            .joined(separator: ",")
        return "\(path.status)|\(active)|v4:\(path.supportsIPv4)|v6:\(path.supportsIPv6)|exp:\(path.isExpensive)|con:\(path.isConstrained)"
    }

}
