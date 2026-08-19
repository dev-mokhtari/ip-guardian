import AppKit
import SwiftUI

enum GuardianPage: String, CaseIterable, Identifiable {
    case dashboard
    case settings
    case logs
    case about

    var id: String { rawValue }

    var title: String {
        switch self {
        case .dashboard: return "Dashboard"
        case .settings: return "Settings"
        case .logs: return "Recent Activity"
        case .about: return "About"
        }
    }

    var symbol: String {
        switch self {
        case .dashboard: return "square.grid.2x2.fill"
        case .settings: return "gearshape.fill"
        case .logs: return "list.bullet.rectangle.fill"
        case .about: return "info.circle.fill"
        }
    }
}

struct MainWindowView: View {
    @ObservedObject var controller: GuardianController
    @State private var selectedPage: GuardianPage = .dashboard

    var body: some View {
        HStack(spacing: 0) {
            GuardianSidebar(controller: controller, selectedPage: $selectedPage)
                .frame(width: 212)

            Rectangle()
                .fill(AppTheme.hairline)
                .frame(width: 1)

            Group {
                switch selectedPage {
                case .dashboard:
                    DashboardView(controller: controller)
                case .settings:
                    SettingsPage(controller: controller)
                case .logs:
                    LogsPage(controller: controller)
                case .about:
                    AboutPage(controller: controller)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(AppTheme.window)
        .preferredColorScheme(.dark)
    }
}

struct MenuContentView: View {
    @ObservedObject var controller: GuardianController
    @Environment(\.openWindow) private var openWindow
    @State private var showCloseConfirmation = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 12) {
                ZStack {
                    RoundedRectangle(cornerRadius: 11, style: .continuous)
                        .fill(statusColor.opacity(0.14))
                    Image(systemName: controller.mode.symbolName)
                        .font(.system(size: 17, weight: .semibold))
                        .foregroundStyle(statusColor)
                }
                .frame(width: 40, height: 40)

                VStack(alignment: .leading, spacing: 3) {
                    Text(controller.mode.title)
                        .font(.headline)
                    Text(menuSubtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .padding(16)

            Rectangle().fill(AppTheme.hairline).frame(height: 1)

            VStack(spacing: 9) {
                menuRow("Public IP", menuIPAddress)
                menuRow(
                    controller.isRetryCycleActive ? "Last verified" : "Location",
                    controller.isRetryCycleActive
                        ? controller.lastVerifiedSummary
                        : menuLocation
                )
                menuRow("Route", menuRoute)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 14)

            if controller.isRetryCycleActive {
                MenuContextCard(tint: statusColor) {
                    Text(controller.lastError ?? "Connection information is incomplete.")
                        .font(.caption.weight(.semibold))
                    RetryCountdown(nextRetryAt: controller.nextRetryAt)
                    Text("Retrying · Attempt \(max(1, controller.retryAttempt)) of \(controller.maximumRetryAttempts)")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(statusColor)
                    Text("Last verified: \(controller.lastVerifiedSummary)")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 12)
            } else if controller.mode == .checking {
                MenuContextCard(tint: statusColor) {
                    Text(checkingMenuTitle)
                        .font(.caption.weight(.semibold))
                    Text("Protected apps are paused during verification.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 12)
            } else if controller.mode == .unsafe,
                      controller.requiresManualClose {
                MenuContextCard(tint: statusColor) {
                    Text(controller.lastError ?? "Connection verification failed.")
                        .font(.caption.weight(.semibold))
                    Text(controller.manualCloseIsRetryExhaustion
                         ? "Automatic retry stopped. Retry Again starts a new three-attempt cycle."
                         : "Protected apps will remain paused until you close them.")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 12)
            } else if controller.mode == .unsafe,
                      let baseline = controller.baseline,
                      let current = controller.current {
                CompactConnectionDelta(
                    trusted: baseline,
                    current: current,
                    fields: controller.changedFields
                )
                .padding(.horizontal, 12)
                .padding(.bottom, 12)
            }

            Rectangle().fill(AppTheme.hairline).frame(height: 1)

            VStack(spacing: 9) {
                if controller.mode == .unsafe,
                   controller.manualCloseIsRetryExhaustion {
                    Button("Retry Again") {
                        controller.retryAgain()
                    }
                    .buttonStyle(MenuPrimaryButtonStyle())
                }

                if (controller.mode == .checking
                    || controller.mode == .unverified
                    || (controller.mode == .unsafe && controller.requiresManualClose)),
                   controller.hasRunningProtectedApps {
                    Button("Close Apps", role: .destructive) {
                        showCloseConfirmation = true
                    }
                    .buttonStyle(MenuDestructiveButtonStyle())
                }

                Button("Open IP Guardian") {
                    openWindow(id: "main")
                    NSApp.activate(ignoringOtherApps: true)
                }
                .buttonStyle(MenuPrimaryButtonStyle())
            }
            .padding(12)

            Text(menuFooter)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 16)
                .padding(.vertical, 11)
                .background(AppTheme.raised.opacity(0.55))
        }
        .frame(width: 360)
        .background(AppTheme.window)
        .alert("Close protected apps?", isPresented: $showCloseConfirmation) {
            Button("Cancel", role: .cancel) {}
            Button("Close Apps", role: .destructive) {
                controller.closeProtectedApps()
            }
        } message: {
            Text("Apps are force closed while still paused, so they never touch the untrusted connection. Unsaved work in them is lost.")
        }
    }

    private var statusColor: Color { AppTheme.statusColor(controller.mode) }

    private var menuSubtitle: String {
        switch controller.mode {
        case .off:
            if controller.isConnectionOverviewLoading, controller.current == nil {
                return "Detecting current connection"
            }
            if controller.current == nil, controller.connectionOverviewError != nil {
                return "Detection failed · retrying automatically"
            }
            return "Live refresh every 10 sec · applications are not monitored"
        case .checking:
            return controller.isRetryCycleActive
                ? "Apps paused · retry cycle active"
                : "Connection verification in progress"
        case .protected: return "Connection verified"
        case .unverified: return "Apps paused · automatic retry"
        case .unsafe:
            if controller.requiresManualClose {
                return controller.manualCloseIsRetryExhaustion
                    ? "Retry limit reached · live monitoring active"
                    : "Manual close required · live monitoring active"
            }
            return "Confirmed change · live monitoring active"
        }
    }

    private var menuIPAddress: String {
        switch controller.mode {
        case .off:
            return controller.current?.ipv4
                ?? (controller.isConnectionOverviewLoading ? "Checking…" : "Unavailable")
        case .unverified: return "Unavailable"
        case .checking: return controller.candidate?.ipv4 ?? "Verifying…"
        case .protected, .unsafe: return controller.current?.ipv4 ?? "—"
        }
    }

    private var menuLocation: String {
        switch controller.mode {
        case .off:
            return controller.current.map { countryLine($0) }
                ?? (controller.isConnectionOverviewLoading ? "Checking…" : "Unavailable")
        case .checking where controller.candidate == nil: return "Checking…"
        default: return countryLine(controller.candidate ?? controller.current)
        }
    }

    private var menuRoute: String {
        controller.currentRouteSummary
    }

    private var checkingMenuTitle: String {
        controller.candidate == nil
            ? "Checking IP, country, route and IPv6…"
            : "Verifying detected connection change…"
    }

    private var menuFooter: String {
        let count = controller.protectedApps.count
        let noun = count == 1 ? "app" : "apps"
        let state: String
        switch controller.appsDisposition {
        case .notProtected: state = "Protection is off"
        case .running: state = "\(count) protected \(noun) running"
        case .paused: state = "\(count) protected \(noun) paused"
        case .closed: state = "Protected apps closed"
        }
        if controller.mode == .off {
            return "\(state) · live connection refresh every 10 sec"
        }
        if controller.mode == .unsafe {
            return "\(state) · live monitoring every \(controller.protectedCheckIntervalText)"
        }
        if controller.isRetryCycleActive {
            return "\(state) · retry attempt \(max(1, controller.retryAttempt)) of \(controller.maximumRetryAttempts)"
        }
        return "\(state) · protected checks every \(controller.protectedCheckIntervalText)"
    }

    private func menuRow(_ label: String, _ value: String) -> some View {
        HStack(alignment: .firstTextBaseline) {
            Text(label).foregroundStyle(.secondary)
            Spacer(minLength: 14)
            Text(value)
                .fontWeight(.semibold)
                .multilineTextAlignment(.trailing)
                .lineLimit(2)
                .textSelection(.enabled)
        }
        .font(.caption)
    }
}

private struct GuardianSidebar: View {
    @ObservedObject var controller: GuardianController
    @Binding var selectedPage: GuardianPage

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 11) {
                // The app icon carries its own shape and shadow, so a container
                // around it only competes and shrinks it.
                Group {
                    if let icon = NSApp.applicationIconImage {
                        Image(nsImage: icon)
                            .resizable()
                            .scaledToFit()
                    } else {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 24, weight: .semibold))
                            .foregroundStyle(AppTheme.safe)
                    }
                }
                .frame(width: 42, height: 42)

                VStack(alignment: .leading, spacing: 2) {
                    Text("IP Guardian")
                        .font(.headline)
                    Text("Connection Protection")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 18)
            .padding(.top, 22)
            .padding(.bottom, 24)

            VStack(spacing: 6) {
                ForEach(GuardianPage.allCases) { page in
                    Button {
                        selectedPage = page
                    } label: {
                        HStack(spacing: 11) {
                            Image(systemName: page.symbol)
                                .frame(width: 18)
                            Text(page.title)
                                .fontWeight(.medium)
                            Spacer()
                        }
                        .foregroundStyle(selectedPage == page ? Color.white : Color.white.opacity(0.56))
                        .padding(.horizontal, 13)
                        .frame(height: 42)
                        .background {
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .fill(selectedPage == page ? AppTheme.selection : .clear)
                        }
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, 10)

            Spacer()

            SidebarStatusCard(controller: controller)
                .padding(12)

            Text("Developed by Amir Mokhtari")
                .font(.caption2)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .center)
                .padding(.horizontal, 12)
                .padding(.bottom, 14)
        }
        .background(AppTheme.sidebar)
    }
}

private struct SidebarStatusCard: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 8) {
                Circle()
                    .fill(statusColor)
                    .frame(width: 8, height: 8)
                    .shadow(color: statusColor.opacity(0.55), radius: 5)
                Text(controller.mode.title.uppercased())
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(statusColor)
                Spacer()
            }

            Text(sidebarDetail)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(13)
        .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 13, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 13, style: .continuous)
                .stroke(AppTheme.hairline, lineWidth: 1)
        }
    }

    private var statusColor: Color { AppTheme.statusColor(controller.mode) }

    private var sidebarDetail: String {
        switch controller.mode {
        case .off: return "Live refresh every 10 sec · applications are not monitored"
        case .checking: return "Apps paused during verification"
        case .protected:
            return "\(controller.policy.title) · checking every \(controller.protectedCheckIntervalText)"
        case .unverified: return "Apps paused · retry cycle active"
        case .unsafe:
            return controller.requiresManualClose
                ? "Unsafe · apps paused · live monitoring active"
                : "Unsafe · apps closed · live monitoring active"
        }
    }
}

private enum DashboardDialog: Identifiable {
    case closeApps

    var id: Int {
        switch self {
        case .closeApps: return 1
        }
    }
}

private struct DashboardView: View {
    @ObservedObject var controller: GuardianController
    @State private var dialog: DashboardDialog?
    @State private var showTurnOffConfirmation = false

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                PageHeader(
                    title: "Dashboard",
                    subtitle: "Real-time connection protection",
                    trailing: monitoringCadence
                )

                StatusHero(
                    controller: controller,
                    dialog: $dialog,
                    showTurnOffConfirmation: $showTurnOffConfirmation
                )

                ConnectionMetrics(controller: controller)

                ProtectionRuleSection(controller: controller)

                ContentSection(title: "Connection path", trailing: pathLocation) {
                    HStack(spacing: 14) {
                        Text("Mac")
                            .foregroundStyle(.secondary)
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.tertiary)
                        Text(pathRoute)
                            .fontWeight(.semibold)
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.tertiary)
                        Text("Internet")
                            .foregroundStyle(.secondary)
                    }
                    .padding(.top, 14)
                }

                ProtectedApplicationsSection(controller: controller)
            }
            .padding(.horizontal, 28)
            .padding(.bottom, 28)
        }
        .background(AppTheme.window)
        .alert(item: $dialog) { value in
            switch value {
            case .closeApps:
                return Alert(
                    title: Text("Close protected apps?"),
                    message: Text("Apps are force closed while still paused, so they never touch the untrusted connection. Unsaved work in them is lost."),
                    primaryButton: .destructive(Text("Close Apps")) {
                        controller.closeProtectedApps()
                    },
                    secondaryButton: .cancel()
                )
            }
        }
        .confirmationDialog(
            "Turn Off Protection?",
            isPresented: $showTurnOffConfirmation,
            titleVisibility: .visible
        ) {
            Button(closeAndTurnOffTitle, role: .destructive) {
                controller.closeAppsAndTurnOffProtection()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The connection is not verified right now, so protected applications cannot be left running. They are force closed and unsaved work in them is lost. Wait for the connection to be verified to turn Protection off without closing them.")
        }
    }

    private var monitoringCadence: String {
        switch controller.mode {
        case .off: return "Live refresh · Every 10 seconds"
        case .unsafe:
            return "Unsafe · Live connection monitoring active"
        default:
            if controller.isRetryCycleActive {
                return "Retry cycle · Attempt \(max(1, controller.retryAttempt)) of \(controller.maximumRetryAttempts)"
            }
            return "Protection active · Every \(controller.protectedCheckIntervalText)"
        }
    }

    private var closeAndTurnOffTitle: String {
        let count = controller.activeProtectedApplicationCount
        if count > 1 { return "Close \(count) Apps & Turn Off" }
        return "Close App & Turn Off"
    }

    private var pathLocation: String {
        if controller.isRetryCycleActive {
            return "Last verified: \(controller.lastVerifiedSummary)"
        }
        if controller.mode == .off {
            return controller.current.map { countryLine($0) }
                ?? (controller.isConnectionOverviewLoading ? "Checking location…" : "Location unavailable")
        }
        return countryLine(controller.candidate ?? controller.current)
    }

    private var pathRoute: String {
        controller.connectionPathSummary
    }
}

private struct StatusHero: View {
    @ObservedObject var controller: GuardianController
    @Binding var dialog: DashboardDialog?
    @Binding var showTurnOffConfirmation: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 16) {
                ZStack {
                    RoundedRectangle(cornerRadius: 15, style: .continuous)
                        .fill(statusColor.opacity(0.13))
                    Image(systemName: controller.mode.symbolName)
                        .font(.system(size: 25, weight: .semibold))
                        .foregroundStyle(statusColor)
                }
                .frame(width: 56, height: 56)

                VStack(alignment: .leading, spacing: 5) {
                    Text(heroTitle)
                        .font(.system(size: 20, weight: .semibold))
                    Text(controller.statusDetail)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer(minLength: 18)
                actions
            }
            .padding(.vertical, 19)

            if controller.isRetryCycleActive {
                UnverifiedNotice(controller: controller)
                    .padding(.bottom, 18)
            } else if controller.mode == .checking,
                      let candidate = controller.candidate,
                      let baseline = controller.baseline {
                ConnectionDelta(
                    trusted: baseline,
                    current: candidate,
                    fields: controller.changedFields,
                    footer: "Verification in progress · apps remain paused"
                )
                .padding(.bottom, 18)
            } else if controller.mode == .unsafe,
                      controller.requiresManualClose {
                RetryExhaustedNotice(controller: controller)
                    .padding(.bottom, 18)
            } else if controller.mode == .unsafe,
                      let baseline = controller.baseline,
                      let current = controller.current {
                ConnectionDelta(
                    trusted: baseline,
                    current: current,
                    fields: controller.changedFields,
                    footer: "Unsafe remains locked · live monitoring active"
                )
                .padding(.bottom, 18)
            }
        }
        .overlay(alignment: .bottom) {
            Rectangle().fill(AppTheme.hairline).frame(height: 1)
        }
    }

    @ViewBuilder
    private var actions: some View {
        switch controller.mode {
        case .off:
            Button("Start Protection") {
                Task { @MainActor in await controller.startProtection() }
            }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(!controller.canStartProtection)
                .opacity(controller.canStartProtection ? 1 : 0.55)
                .help(controller.protectionStartRequirement ?? "Start Protection")
        case .protected:
            Button("Turn Off Protection") { requestTurnOff() }
            .buttonStyle(GhostActionButtonStyle())
        case .unsafe:
            if controller.manualCloseIsRetryExhaustion {
                HStack(spacing: 9) {
                    Button("Retry Again") { controller.retryAgain() }
                        .buttonStyle(PrimaryActionButtonStyle())
                    Button("Turn Off Protection") { requestTurnOff() }
                        .buttonStyle(GhostActionButtonStyle())
                    if controller.hasRunningProtectedApps {
                        Button("Close Apps") { dialog = .closeApps }
                            .buttonStyle(DangerActionButtonStyle())
                    }
                }
            } else if controller.requiresManualClose && controller.hasRunningProtectedApps {
                    Button("Close Apps") { dialog = .closeApps }
                        .buttonStyle(DangerActionButtonStyle())
            } else {
                Button("Turn Off Protection") { requestTurnOff() }
                .buttonStyle(GhostActionButtonStyle())
            }
        case .checking, .unverified:
            HStack(spacing: 9) {
                Button("Turn Off Protection") { requestTurnOff() }
                .buttonStyle(GhostActionButtonStyle())
                if controller.hasRunningProtectedApps {
                    Button("Close Apps") { dialog = .closeApps }
                        .buttonStyle(DangerActionButtonStyle())
                }
            }
        }
    }

    private func requestTurnOff() {
        Task { @MainActor in
            if !(await controller.turnOffProtection()) {
                showTurnOffConfirmation = true
            }
        }
    }

    private var heroTitle: String {
        switch controller.mode {
        case .off: return "Protection is off"
        case .checking:
            return controller.isRetryCycleActive
                ? "Retrying connection"
                : "Checking connection"
        case .protected: return "Connection verified"
        case .unverified: return "Connection unverified"
        case .unsafe:
            return controller.requiresManualClose
                ? "Unsafe connection"
                : "Unsafe connection confirmed"
        }
    }

    private var statusColor: Color { AppTheme.statusColor(controller.mode) }
}

private struct UnverifiedNotice: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(AppTheme.warning)
                    .padding(.top, 1)
                VStack(alignment: .leading, spacing: 4) {
                    Text(controller.lastError ?? "Connection information is incomplete.")
                        .font(.callout.weight(.semibold))
                    Text("Last verified: \(controller.lastVerifiedSummary)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
            }

            RetryCountdown(nextRetryAt: controller.nextRetryAt)
                .padding(.leading, 28)
        }
        .padding(14)
        .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(AppTheme.warning.opacity(0.22), lineWidth: 1)
        }
    }
}

private struct RetryExhaustedNotice: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: "xmark.shield.fill")
                .foregroundStyle(AppTheme.danger)
            VStack(alignment: .leading, spacing: 5) {
                Text(controller.lastError ?? "Connection verification failed after three retries.")
                    .font(.callout.weight(.semibold))
                Text(controller.hasRunningProtectedApps
                     ? (controller.manualCloseIsRetryExhaustion
                        ? "Automatic retry has stopped. Live connection monitoring continues; use Retry Again for another three attempts, or close the paused apps."
                        : "Some protected processes could not be closed. Live connection monitoring continues while they remain paused.")
                     : "Automatic retry has stopped. Live connection monitoring continues; use Retry Again to run another three verification attempts.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(AppTheme.danger.opacity(0.28), lineWidth: 1)
        }
    }
}

private struct RetryCountdown: View {
    let nextRetryAt: Date?

    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            Text(countdownText(at: context.date))
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private func countdownText(at date: Date) -> String {
        guard let nextRetryAt else { return "Verification request in progress…" }
        let seconds = max(0, Int(ceil(nextRetryAt.timeIntervalSince(date))))
        return seconds == 0
            ? "Retrying automatically…"
            : "Retrying automatically · next attempt in \(seconds) sec"
    }
}

private struct ConnectionDelta: View {
    let trusted: IPObservation
    let current: IPObservation
    let fields: [String]
    let footer: String

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 0) {
                deltaZone("Trusted connection", observation: trusted)
                    .frame(maxWidth: .infinity)
                Image(systemName: "arrow.right")
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(AppTheme.statusColor(.checking))
                    .frame(width: 56)
                deltaZone("Current connection", observation: current)
                    .frame(maxWidth: .infinity)
            }
            .frame(maxWidth: .infinity)

            HStack {
                Text("Changed fields: \(fields.isEmpty ? "Connection details" : fields.joined(separator: " · "))")
                Spacer()
                Text(footer)
            }
            .font(.caption2)
            .foregroundStyle(.secondary)
        }
        .padding(14)
        .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(AppTheme.hairline, lineWidth: 1)
        }
    }

    private func deltaZone(_ label: String, observation: IPObservation) -> some View {
        ZStack {
            CountryFlagBackground(countryCode: observation.countryLabel)

            HStack {
                Spacer(minLength: 20)
                VStack(alignment: .leading, spacing: 4) {
                    Text(label)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                    Text(observation.ipv4)
                        .font(.callout.weight(.semibold))
                        .textSelection(.enabled)
                }
                Spacer(minLength: 20)
            }
        }
        .frame(maxWidth: .infinity, minHeight: 58)
        .clipped()
    }
}

private struct CompactConnectionDelta: View {
    let trusted: IPObservation
    let current: IPObservation
    let fields: [String]

    var body: some View {
        MenuContextCard(tint: AppTheme.danger) {
            HStack(spacing: 0) {
                compactZone("TRUSTED", observation: trusted)
                    .frame(maxWidth: .infinity, alignment: .leading)
                Image(systemName: "arrow.right")
                    .foregroundStyle(AppTheme.danger)
                    .frame(width: 34)
                compactZone("CURRENT", observation: current)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .frame(maxWidth: .infinity)
            Text(fields.isEmpty
                 ? "Current connection matches Trusted · Unsafe remains locked"
                 : "Changed: \(fields.joined(separator: " · "))")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    private func compactZone(_ label: String, observation: IPObservation) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 9, weight: .bold))
                .foregroundStyle(.secondary)
            Text(countryName(observation.countryLabel))
                .font(.caption.weight(.semibold))
                .lineLimit(1)
            Text(observation.ipv4)
                .font(.caption2.monospaced())
                .lineLimit(1)
                .minimumScaleFactor(0.78)
        }
    }
}

private struct ConnectionMetrics: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        HStack(spacing: 0) {
            metric(
                "Public IPv4",
                ipv4Value,
                countryCode: displayedIPv4Observation?.countryLabel,
                monospaced: true,
                showsDivider: true
            )
            metric("IPv6", ipv6Value, monospaced: false, showsDivider: true)
            metric("Current route", routeValue, monospaced: false, showsDivider: true)
            metric("Last check", lastCheckValue, monospaced: false)
        }
        .frame(height: 112)
        .background {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(AppTheme.raised)
        }
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(Color.white.opacity(0.22), lineWidth: 1.5)
        }
        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
        .padding(.vertical, 19)
    }

    private var activeObservation: IPObservation? {
        controller.candidate ?? controller.current
    }

    private var displayedIPv4Observation: IPObservation? {
        switch controller.mode {
        case .off: return controller.current
        case .unverified: return nil
        case .checking: return controller.candidate
        case .protected, .unsafe: return controller.current
        }
    }

    private var ipv4Value: String {
        if let observation = displayedIPv4Observation {
            return observation.ipv4
        }
        switch controller.mode {
        case .off:
            return controller.isConnectionOverviewLoading ? "Checking…" : "Unavailable"
        case .unverified: return "Unavailable"
        case .checking: return "Verifying…"
        case .protected, .unsafe: return "—"
        }
    }

    private var ipv6Value: String {
        switch controller.mode {
        case .off where controller.isConnectionOverviewLoading && activeObservation == nil:
            return "Checking…"
        case .unverified: return "Unknown"
        case .checking where activeObservation == nil: return "Verifying…"
        default:
            guard let observation = activeObservation else { return "—" }
            if observation.ipv6LeakStatus == .leakDetected {
                return "Leak detected"
            }
            return observation.ipv6 ?? observation.ipv6LeakStatus.displayName
        }
    }

    private var routeValue: String {
        controller.currentRouteSummary
    }

    private var lastCheckValue: String {
        if controller.mode == .off {
            if controller.isConnectionOverviewLoading { return "In progress" }
            if controller.current == nil, controller.connectionOverviewError != nil {
                return "Request failed"
            }
            return controller.lastCheckAt?.formatted(date: .omitted, time: .standard) ?? "—"
        }
        if controller.mode == .checking { return "In progress" }
        if controller.mode == .unverified { return "Request failed" }
        return controller.lastCheckAt?.formatted(date: .omitted, time: .standard) ?? "—"
    }

    private func metric(
        _ label: String,
        _ value: String,
        countryCode: String? = nil,
        monospaced: Bool,
        showsDivider: Bool = false
    ) -> some View {
        VStack(alignment: .leading, spacing: 7) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(monospaced
                      ? .system(size: 15, weight: .semibold, design: .monospaced)
                      : .system(size: 15, weight: .semibold))
                .lineLimit(2)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .padding(15)
        .background {
            CountryFlagBackground(countryCode: countryCode)
        }
        .overlay(alignment: .trailing) {
            if showsDivider {
                Rectangle()
                    .fill(Color.white.opacity(0.14))
                    .frame(width: 1)
            }
        }
    }
}

private struct CountryFlagBackground: View {
    let countryCode: String?

    var body: some View {
        GeometryReader { proxy in
            if let image = CountryFlagImage.image(for: countryCode) {
                ZStack {
                    Image(nsImage: image)
                        .resizable()
                        .aspectRatio(contentMode: .fill)
                        .frame(width: proxy.size.width, height: proxy.size.height)
                        .blur(radius: 16)
                        .scaleEffect(1.08)
                        .saturation(0.25)
                        .brightness(-0.14)
                        .opacity(0.07)

                    Image(nsImage: image)
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                        .frame(width: proxy.size.width, height: proxy.size.height)
                        .saturation(0.18)
                        .brightness(-0.10)
                        .opacity(0.11)
                }
                .frame(width: proxy.size.width, height: proxy.size.height)
            }
        }
        .clipped()
        .accessibilityHidden(true)
        .allowsHitTesting(false)
    }
}

private struct ProtectionRuleSection: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        ContentSection(title: "Protection rule", trailing: cadence) {
            HStack(spacing: 12) {
                ruleItem(
                    label: "Protection mode",
                    value: controller.policy.title,
                    symbol: controller.policy == .sameCountry
                        ? "globe.europe.africa.fill"
                        : "lock.fill"
                )

                ruleItem(
                    label: protectedValueLabel,
                    value: protectedValue,
                    symbol: controller.policy == .sameCountry
                        ? "mappin.and.ellipse"
                        : "network"
                )
            }
            .padding(.top, 14)
        }
    }

    private var cadence: String {
        switch controller.mode {
        case .off:
            return "Starts with Protection"
        case .unsafe:
            return "Live monitoring · Every \(controller.protectedCheckIntervalText)"
        default:
            return "Security check · Every \(controller.protectedCheckIntervalText)"
        }
    }

    private var protectedValueLabel: String {
        if controller.policy == .sameCountry { return "Allowed countries" }
        // Before Start there is no protected address yet, and labelling the
        // live one "Protected" would claim a guarantee that does not exist.
        return controller.mode == .off ? "Current IP" : "Protected IP"
    }

    private var protectedValue: String {
        // The allowed list is a choice, not a discovery: it reads the same
        // before and during Protection.
        if controller.policy == .sameCountry {
            return controller.allowedCountriesSummary
        }
        guard controller.mode != .off else {
            return controller.current?.ipv4
                ?? (controller.isConnectionOverviewLoading ? "Checking…" : "Unavailable")
        }
        guard let baseline = controller.baseline else {
            return "Creating trusted baseline…"
        }
        return baseline.ipv4
    }

    private func ruleItem(
        label: String,
        value: String,
        symbol: String
    ) -> some View {
        HStack(spacing: 11) {
            Image(systemName: symbol)
                .font(.system(size: 16, weight: .semibold))
                .foregroundStyle(AppTheme.systemBlue)
                .frame(width: 22)
            VStack(alignment: .leading, spacing: 4) {
                Text(label)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                Text(value)
                    .font(.callout.weight(.semibold))
                    .lineLimit(2)
                    .textSelection(.enabled)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxWidth: .infinity, minHeight: 68, alignment: .leading)
        .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .stroke(AppTheme.hairline, lineWidth: 1)
        }
    }
}

private struct ContentSection<Content: View>: View {
    let title: String
    let trailing: String
    let content: Content

    init(
        title: String,
        trailing: String,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.trailing = trailing
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text(title).font(.headline)
                Spacer()
                Text(trailing)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            content
        }
        .padding(.vertical, 19)
        .overlay(alignment: .bottom) {
            Rectangle().fill(AppTheme.hairline).frame(height: 1)
        }
    }
}

private struct ProtectedApplicationsSection: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        VStack(alignment: .leading, spacing: 13) {
            HStack {
                Text("Protected applications").font(.headline)
                Spacer()
                Button("Add Application") { chooseApplication() }
                    .buttonStyle(GhostActionButtonStyle())
            }

            if let notice = controller.applicationNotice {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: "exclamationmark.circle.fill")
                        .foregroundStyle(AppTheme.warning)
                        .padding(.top, 1)
                    Text(notice)
                        .font(.callout)
                        .fixedSize(horizontal: false, vertical: true)
                    Spacer(minLength: 0)
                }
                .padding(13)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(
                    AppTheme.warning.opacity(0.09),
                    in: RoundedRectangle(cornerRadius: 12, style: .continuous)
                )
                .overlay {
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .stroke(AppTheme.warning.opacity(0.30), lineWidth: 1)
                }
                .transition(.opacity)
            }

            if controller.protectedApps.isEmpty {
                HStack(spacing: 11) {
                    Image(systemName: "plus.app")
                        .foregroundStyle(.secondary)
                    Text("No applications selected. Add any .app bundle to protect it.")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                .padding(15)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
            } else {
                VStack(spacing: 8) {
                    ForEach(controller.protectedApps) { app in
                        HStack(spacing: 12) {
                            Image(nsImage: NSWorkspace.shared.icon(forFile: app.path))
                                .resizable()
                                .frame(width: 34, height: 34)
                                .clipShape(RoundedRectangle(cornerRadius: 7, style: .continuous))

                            VStack(alignment: .leading, spacing: 3) {
                                Text(app.name).fontWeight(.semibold)
                                Text("Includes child processes and helpers")
                                    .font(.caption2)
                                    .foregroundStyle(.secondary)
                            }
                            Spacer()
                            HStack(spacing: 7) {
                                Circle()
                                    .fill(AppTheme.statusColor(controller.mode))
                                    .frame(width: 7, height: 7)
                                Text(controller.runtimeState(for: app).title)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                            Button(role: .destructive) {
                                controller.removeApplication(app)
                            } label: {
                                Image(systemName: "trash")
                            }
                            .buttonStyle(.plain)
                            .foregroundStyle(controller.isProtectionActive ? Color.secondary : AppTheme.danger)
                            .disabled(controller.isProtectionActive)
                            .help(controller.isProtectionActive
                                  ? "Turn off Protection before removing an app."
                                  : "Remove application")
                        }
                        .padding(13)
                        .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 12, style: .continuous)
                                .stroke(AppTheme.hairline, lineWidth: 1)
                        }
                    }
                }
            }
        }
        .padding(.top, 19)
        .animation(.easeInOut(duration: 0.2), value: controller.applicationNotice)
    }

    private func chooseApplication() {
        let panel = NSOpenPanel()
        panel.title = "Choose applications to protect"
        panel.prompt = "Add"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.allowedContentTypes = [.applicationBundle]
        panel.directoryURL = URL(fileURLWithPath: "/Applications")
        guard panel.runModal() == .OK else { return }
        for url in panel.urls { controller.addApplication(at: url) }
    }
}

private struct SettingsPage: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                PageHeader(
                    title: "Settings",
                    subtitle: "Choose the connection policy used for Protection",
                    trailing: nil
                )

                SettingsSection(
                    title: "IP change policy",
                    detail: "Choose what counts as a trusted connection after the baseline is created."
                ) {
                    HStack(spacing: 12) {
                        PolicyCard(
                            title: "Exact IP",
                            detail: "Any confirmed public IPv4 change is unsafe.",
                            symbol: "lock.fill",
                            selected: controller.policy == .exactIP,
                            disabled: controller.isPolicyLocked
                        ) {
                            controller.updatePolicy(.exactIP)
                        }
                        PolicyCard(
                            title: "Same Country",
                            detail: "Allow a rotating IP while the country and route stay the same.",
                            symbol: "globe.europe.africa.fill",
                            selected: controller.policy == .sameCountry,
                            disabled: controller.isPolicyLocked
                        ) {
                            controller.updatePolicy(.sameCountry)
                        }
                    }
                    .padding(.top, 15)

                    Label(
                        controller.isPolicyLocked
                            ? "Policy is locked while Protection is active."
                            : "Policy can be changed before Protection starts.",
                        systemImage: controller.isPolicyLocked ? "lock.fill" : "lock.open.fill"
                    )
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .padding(.top, 11)
                }

                if controller.policy == .sameCountry {
                    SettingsSection(title: "", detail: "") {
                        AllowedCountriesPicker(controller: controller)
                    }
                }

            }
            .padding(.horizontal, 28)
            .padding(.bottom, 28)
        }
        .background(AppTheme.window)
    }
}

/// Every country the system knows, paired with the flag that ships with the app.
private struct SelectableCountry: Identifiable, Hashable {
    let code: String
    let name: String
    var id: String { code }

    static let all: [SelectableCountry] = {
        Locale.Region.isoRegions
            .map(\.identifier)
            .compactMap { CountryCode.resolved($0) }
            .filter { CountryFlagImage.exists(for: $0) }
            .map { code in
                SelectableCountry(
                    code: code,
                    name: Locale.current.localizedString(forRegionCode: code) ?? code
                )
            }
            .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }()
}

private struct CountryFlagBadge: View {
    let code: String
    var height: CGFloat = 14

    var body: some View {
        Group {
            if let image = CountryFlagImage.image(for: code) {
                Image(nsImage: image).resizable().scaledToFill()
            } else {
                Rectangle().fill(AppTheme.raised)
            }
        }
        .frame(width: height * 1.5, height: height)
        .clipShape(RoundedRectangle(cornerRadius: 2, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 2, style: .continuous)
                .stroke(Color.white.opacity(0.18), lineWidth: 0.5)
        }
    }
}

private struct AllowedCountriesPicker: View {
    @ObservedObject var controller: GuardianController
    @State private var draft: [String] = []
    @State private var search = ""
    @State private var loadedFor: [String] = []

    /// Four across, ten deep. Enough to browse without turning the settings
    /// page into a wall of 252 rows; anything past it is a search away.
    private static let columnCount = 4
    private static let visibleRowCount = 8
    private static let visibleLimit = columnCount * visibleRowCount

    private var pool: [SelectableCountry] {
        SelectableCountry.all.filter { !draft.contains($0.code) }
    }

    private var filtered: [SelectableCountry] {
        let query = search.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return pool }
        return pool.filter { $0.name.localizedCaseInsensitiveContains(query) }
    }

    private var matches: [SelectableCountry] {
        Array(filtered.prefix(Self.visibleLimit))
    }

    private var listCaption: String {
        let total = filtered.count
        if !search.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return total == 0
                ? "No country matches that name"
                : "\(total) \(total == 1 ? "match" : "matches")"
        }
        return total > Self.visibleLimit
            ? "\(matches.count) of \(total) countries · search for any other"
            : "\(total) countries"
    }

    private var isFull: Bool { draft.count >= AllowedCountries.maximumCount }
    private var hasUnsavedChanges: Bool { draft != controller.allowedCountries }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline) {
                Text("Allowed countries").font(.headline)
                Spacer()
                Text("\(draft.count) of \(AllowedCountries.maximumCount) selected")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text("Protection starts once the list is saved. A connection in any other country is closed.")
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.top, 4)

            if !draft.isEmpty {
                HStack(spacing: 8) {
                    ForEach(draft, id: \.self) { code in
                        chip(code)
                    }
                    Spacer(minLength: 0)
                }
                .padding(.top, 13)
            }

            HStack(spacing: 8) {
                Image(systemName: "magnifyingglass")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                TextField("Search countries", text: $search)
                    .textFieldStyle(.plain)
                Text(listCaption)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            .padding(.horizontal, 11)
            .padding(.vertical, 8)
            .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 9, style: .continuous))
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(AppTheme.hairline, lineWidth: 1)
            }
            .padding(.top, 13)
            .disabled(controller.isPolicyLocked)

            if isFull {
                Label(
                    "Remove a country to choose a different one.",
                    systemImage: "info.circle"
                )
                .font(.caption)
                .foregroundStyle(.secondary)
                .padding(.top, 10)
            }

            LazyVGrid(
                columns: Array(
                    repeating: GridItem(.flexible(), spacing: 8),
                    count: Self.columnCount
                ),
                spacing: 8
            ) {
                ForEach(matches) { country in
                    Button {
                        guard !isFull, !controller.isPolicyLocked else { return }
                        draft.append(country.code)
                        search = ""
                    } label: {
                        HStack(spacing: 8) {
                            CountryFlagBadge(code: country.code)
                            Text(country.name)
                                .font(.caption)
                                .lineLimit(1)
                                .truncationMode(.tail)
                            Spacer(minLength: 0)
                        }
                        .padding(.horizontal, 9)
                        .padding(.vertical, 8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                        .overlay {
                            RoundedRectangle(cornerRadius: 8, style: .continuous)
                                .stroke(AppTheme.hairline, lineWidth: 1)
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .help(country.name)
                }
            }
            .padding(.top, 10)
            // The list stays put when the limit is reached: hiding it looks
            // like a fault, and the user still needs to see what is on offer.
            .opacity(isFull || controller.isPolicyLocked ? 0.4 : 1)
            .allowsHitTesting(!isFull && !controller.isPolicyLocked)

            HStack(spacing: 12) {
                Button("Save allowed countries") {
                    controller.updateAllowedCountries(draft)
                }
                .buttonStyle(PrimaryActionButtonStyle())
                .disabled(controller.isPolicyLocked || draft.isEmpty || !hasUnsavedChanges)
                .opacity(controller.isPolicyLocked || draft.isEmpty || !hasUnsavedChanges ? 0.55 : 1)

                if controller.isPolicyLocked {
                    Label("Locked while Protection is active.", systemImage: "lock.fill")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                } else if hasUnsavedChanges {
                    Label(
                        draft.isEmpty
                            ? "Choose at least one country."
                            : "Unsaved — Protection cannot start yet.",
                        systemImage: "exclamationmark.triangle.fill"
                    )
                    .font(.caption)
                    .foregroundStyle(AppTheme.warning)
                } else {
                    Label("Saved.", systemImage: "checkmark.circle.fill")
                        .font(.caption)
                        .foregroundStyle(AppTheme.safe)
                }
                Spacer(minLength: 0)
            }
            .padding(.top, 15)
        }
        .onAppear(perform: syncDraft)
        .onChange(of: controller.allowedCountries) { _ in syncDraft() }
    }

    private func syncDraft() {
        guard loadedFor != controller.allowedCountries else { return }
        loadedFor = controller.allowedCountries
        draft = controller.allowedCountries
    }

    private func chip(_ code: String) -> some View {
        HStack(spacing: 7) {
            CountryFlagBadge(code: code)
            Text(countryName(code)).font(.caption)
            Button {
                draft.removeAll { $0 == code }
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 9, weight: .bold))
            }
            .buttonStyle(.plain)
            .foregroundStyle(.secondary)
            .disabled(controller.isPolicyLocked)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 6)
        .background(AppTheme.systemBlue.opacity(0.16), in: Capsule())
        .overlay { Capsule().stroke(AppTheme.systemBlue.opacity(0.35), lineWidth: 1) }
    }
}

private struct AboutPage: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        ScrollView {
            VStack(spacing: 0) {
                PageHeader(
                    title: "About IP Guardian",
                    subtitle: "A focused connection-safety layer for macOS",
                    trailing: versionLabel
                )

                SettingsSection(
                    title: "What it does",
                    detail: "IP Guardian watches the connection your chosen applications are using, and stops them the instant it stops being the one you trusted."
                ) {
                    EmptyView()
                }

                SettingsSection(
                    title: "Two ways to define the connection you trust",
                    detail: "Whichever rule you pick, the route itself is always watched: if the VPN or proxy drops, your apps are closed regardless."
                ) {
                    VStack(spacing: 12) {
                        BehaviorRow(
                            title: "Exact IP",
                            detail: "The strictest rule. The public address has to stay exactly what it was when Protection started. Best when your VPN or proxy gives you one stable exit."
                        )
                        BehaviorRow(
                            title: "Same Country",
                            detail: "The address may change as often as it likes, as long as the connection stays in one of up to three countries you choose. Best when your VPN or proxy moves between exits — a VPN left on automatic, or a proxy that answers from several exits at once."
                        )
                    }
                    .padding(.top, 15)
                }

                SettingsSection(
                    title: "Why you can leave your apps with it",
                    detail: ""
                ) {
                    VStack(spacing: 12) {
                        BehaviorRow(
                            title: "Freezes first, asks questions second",
                            detail: "The moment the network changes, your protected apps are frozen — before anything is known about the new connection. Checking happens while they are already stopped, not before."
                        )
                        BehaviorRow(
                            title: "Never closes an app on a guess",
                            detail: "A timeout, an unreachable service or a brief outage never closes anything. Apps wait, frozen, until the connection is verified again."
                        )
                        BehaviorRow(
                            title: "Agreement, then confirmation",
                            detail: "Independent services have to agree on what they see, and a change has to be confirmed repeatedly before a single application is closed."
                        )
                        BehaviorRow(
                            title: "Survives its own failure",
                            detail: "If IP Guardian is force quit or crashes while your apps are frozen, they are released automatically. Nothing stays stuck."
                        )
                    }
                    .padding(.top, 15)
                }

                SettingsSection(
                    title: "What it watches",
                    detail: "Beyond the public address, IP Guardian watches the route your traffic actually takes — VPN, proxy or direct — and looks for traffic slipping around it over IPv6. A changed address is not the only way a connection stops being the one you trusted."
                ) {
                    EmptyView()
                }

                SettingsSection(
                    title: "Important limitation",
                    detail: "IP Guardian is a monitoring and rapid-response safety layer, not a system-level firewall or direct network kill switch."
                ) {
                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: "exclamationmark.shield.fill")
                            .font(.system(size: 20, weight: .semibold))
                            .foregroundStyle(AppTheme.warning)
                            .padding(.top, 1)
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Protection is not guaranteed 100%")
                                .fontWeight(.semibold)
                            Text("A protected app may still send a small amount of data before macOS reports a network change and IP Guardian reacts. A system firewall or Network Extension is required for a true zero-packet kill switch.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(15)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(AppTheme.warning.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(AppTheme.warning.opacity(0.28), lineWidth: 1)
                    }
                    .padding(.top, 15)

                    HStack(alignment: .top, spacing: 12) {
                        Image(systemName: "network.slash")
                            .font(.system(size: 20, weight: .semibold))
                            .foregroundStyle(AppTheme.warning)
                            .padding(.top, 1)
                        VStack(alignment: .leading, spacing: 6) {
                            Text("A restricted network can stop verification")
                                .fontWeight(.semibold)
                            Text("Confirming where your traffic leaves from means asking several independent services on the internet. If your network or proxy only carries part of the internet, some cannot be reached and IP Guardian reports that the connection could not be verified — even while your browsing works perfectly.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                            Text("Nothing is closed when that happens. Protected apps stay frozen, verification keeps retrying, and they resume as soon as the connection is confirmed again.")
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .padding(15)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(AppTheme.warning.opacity(0.08), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay {
                        RoundedRectangle(cornerRadius: 12, style: .continuous)
                            .stroke(AppTheme.warning.opacity(0.28), lineWidth: 1)
                    }
                    .padding(.top, 11)
                }

                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Developed by Amir Mokhtari")
                            .font(.headline)
                        Text("Developer email: dev.mokhtari@gmail.com")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                        Text("IP Guardian for macOS · \(versionLabel)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 28, weight: .semibold))
                        .foregroundStyle(AppTheme.safe)
                }
                .padding(.vertical, 19)
            }
            .padding(.horizontal, 28)
            .padding(.bottom, 28)
        }
        .background(AppTheme.window)
    }

    private var versionLabel: String {
        let version = Bundle.main.object(
            forInfoDictionaryKey: "CFBundleShortVersionString"
        ) as? String ?? "1"
        return "Version \(version)"
    }
}

private struct SettingsSection<Content: View>: View {
    let title: String
    let detail: String
    let content: Content

    init(title: String, detail: String, @ViewBuilder content: () -> Content) {
        self.title = title
        self.detail = detail
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            if !detail.isEmpty {
                Text(detail)
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            content
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.vertical, 19)
        .overlay(alignment: .bottom) {
            Rectangle().fill(AppTheme.hairline).frame(height: 1)
        }
    }
}

private struct PolicyCard: View {
    let title: String
    let detail: String
    let symbol: String
    let selected: Bool
    let disabled: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: symbol)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(selected ? AppTheme.systemBlue : Color.secondary)
                    .frame(width: 22)
                VStack(alignment: .leading, spacing: 5) {
                    Text(title).fontWeight(.semibold)
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .foregroundStyle(selected ? AppTheme.systemBlue : Color.secondary.opacity(0.5))
            }
            .padding(15)
            .frame(maxWidth: .infinity, minHeight: 88, alignment: .topLeading)
            .background(
                selected ? AppTheme.systemBlue.opacity(0.08) : AppTheme.raised,
                in: RoundedRectangle(cornerRadius: 12, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .stroke(
                        selected ? AppTheme.systemBlue.opacity(0.38) : AppTheme.hairline,
                        lineWidth: 1
                    )
            }
        }
        .buttonStyle(.plain)
        .disabled(disabled)
        .opacity(disabled ? 0.68 : 1)
    }
}

private struct BehaviorRow: View {
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 11) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(AppTheme.safe)
                .padding(.top, 1)
            VStack(alignment: .leading, spacing: 3) {
                Text(title).fontWeight(.semibold)
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
    }
}

private struct LogsPage: View {
    @ObservedObject var controller: GuardianController

    var body: some View {
        VStack(spacing: 0) {
            PageHeader(
                title: "Recent Activity",
                subtitle: "Up to 200 important events from this IP Guardian session",
                trailing: nil
            ) {
                Button("Clear Activity") { controller.clearEvents() }
                    .buttonStyle(GhostActionButtonStyle())
            }

            HStack {
                Text("TIME").frame(width: 92, alignment: .leading)
                Text("LEVEL").frame(width: 82, alignment: .leading)
                Text("EVENT")
                Spacer()
            }
            .font(.caption2.weight(.bold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 14)
            .frame(height: 38)
            .background(AppTheme.raised)

            if controller.events.isEmpty {
                VStack(spacing: 10) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 30, weight: .light))
                        .foregroundStyle(.secondary)
                    Text("No recent activity")
                        .foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(controller.events) { event in
                            LogRow(event: event)
                            Rectangle().fill(AppTheme.hairline).frame(height: 1)
                        }
                    }
                }
            }
        }
        .padding(.horizontal, 28)
        .padding(.bottom, 28)
        .background(AppTheme.window)
    }
}

private struct LogRow: View {
    let event: EventRecord

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            Text(Self.timeFormatter.string(from: event.date))
                .font(.caption.monospacedDigit())
                .foregroundStyle(.secondary)
                .frame(width: 92, alignment: .leading)

            HStack(spacing: 6) {
                Circle().fill(levelColor).frame(width: 7, height: 7)
                Text(event.level)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(levelColor)
            }
            .frame(width: 82, alignment: .leading)

            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(event.message)
                    .font(.callout)
                    .textSelection(.enabled)
                if event.occurrenceCount > 1 {
                    Text("×\(event.occurrenceCount)")
                        .font(.caption2.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(AppTheme.raised, in: Capsule())
                }
                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
    }

    private var levelColor: Color {
        switch event.level {
        case "CRITICAL", "ERROR": return AppTheme.danger
        case "WARN": return AppTheme.warning
        case "INFO": return AppTheme.safe
        default: return AppTheme.systemBlue
        }
    }

    private static let timeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.timeStyle = .medium
        return formatter
    }()
}

private struct PageHeader<Trailing: View>: View {
    let title: String
    let subtitle: String
    let trailing: String?
    let trailingContent: Trailing

    init(
        title: String,
        subtitle: String,
        trailing: String?,
        @ViewBuilder trailingContent: () -> Trailing
    ) {
        self.title = title
        self.subtitle = subtitle
        self.trailing = trailing
        self.trailingContent = trailingContent()
    }

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 26, weight: .bold))
                Text(subtitle)
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if let trailing {
                Text(trailing)
                    .font(.caption.weight(.semibold))
                    .padding(.horizontal, 10)
                    .padding(.vertical, 6)
                    .background(AppTheme.raised, in: Capsule())
                    .overlay { Capsule().stroke(AppTheme.hairline, lineWidth: 1) }
            }
            trailingContent
        }
        .padding(.top, 28)
        .padding(.bottom, 18)
        .overlay(alignment: .bottom) {
            Rectangle().fill(AppTheme.hairline).frame(height: 1)
        }
    }
}

private extension PageHeader where Trailing == EmptyView {
    init(title: String, subtitle: String, trailing: String?) {
        self.init(title: title, subtitle: subtitle, trailing: trailing) { EmptyView() }
    }
}

private struct MenuContextCard<Content: View>: View {
    let tint: Color
    let content: Content

    init(tint: Color, @ViewBuilder content: () -> Content) {
        self.tint = tint
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            content
        }
        .padding(11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(AppTheme.raised, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .overlay {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(tint.opacity(0.20), lineWidth: 1)
        }
    }
}

private enum AppTheme {
    static let window = Color(nsColor: NSColor(calibratedRed: 0.055, green: 0.057, blue: 0.063, alpha: 1))
    static let sidebar = Color(nsColor: NSColor(calibratedRed: 0.071, green: 0.073, blue: 0.080, alpha: 1))
    static let raised = Color(nsColor: NSColor(calibratedRed: 0.098, green: 0.101, blue: 0.110, alpha: 1))
    static let selection = Color.white.opacity(0.075)
    static let hairline = Color.white.opacity(0.075)
    static let systemBlue = Color(nsColor: NSColor.systemBlue)
    static let safe = Color(nsColor: NSColor(calibratedRed: 0.20, green: 0.78, blue: 0.42, alpha: 1))
    static let warning = Color(nsColor: NSColor(calibratedRed: 1.00, green: 0.62, blue: 0.18, alpha: 1))
    static let danger = Color(nsColor: NSColor(calibratedRed: 1.00, green: 0.32, blue: 0.35, alpha: 1))

    static func statusColor(_ mode: GuardianMode) -> Color {
        switch mode {
        case .off: return Color.secondary
        case .checking: return systemBlue
        case .protected: return safe
        case .unverified: return warning
        case .unsafe: return danger
        }
    }
}

private struct PrimaryActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.semibold))
            .padding(.horizontal, 16)
            .frame(height: 37)
            .foregroundStyle(.white)
            .background(
                AppTheme.systemBlue.opacity(configuration.isPressed ? 0.72 : 1),
                in: RoundedRectangle(cornerRadius: 9, style: .continuous)
            )
    }
}

private struct GhostActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.medium))
            .padding(.horizontal, 14)
            .frame(height: 36)
            .background(
                Color.white.opacity(configuration.isPressed ? 0.10 : 0.055),
                in: RoundedRectangle(cornerRadius: 9, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(AppTheme.hairline, lineWidth: 1)
            }
    }
}

private struct DangerActionButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.semibold))
            .padding(.horizontal, 14)
            .frame(height: 36)
            .foregroundStyle(AppTheme.danger)
            .background(
                AppTheme.danger.opacity(configuration.isPressed ? 0.16 : 0.09),
                in: RoundedRectangle(cornerRadius: 9, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(AppTheme.danger.opacity(0.30), lineWidth: 1)
            }
    }
}

private struct MenuPrimaryButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.semibold))
            .frame(maxWidth: .infinity)
            .frame(height: 36)
            .foregroundStyle(.white)
            .background(
                AppTheme.systemBlue.opacity(configuration.isPressed ? 0.72 : 1),
                in: RoundedRectangle(cornerRadius: 9, style: .continuous)
            )
    }
}

private struct MenuDestructiveButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.callout.weight(.semibold))
            .frame(maxWidth: .infinity)
            .frame(height: 36)
            .foregroundStyle(AppTheme.danger)
            .background(
                AppTheme.danger.opacity(configuration.isPressed ? 0.16 : 0.09),
                in: RoundedRectangle(cornerRadius: 9, style: .continuous)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .stroke(AppTheme.danger.opacity(0.30), lineWidth: 1)
            }
    }
}

private func countryName(_ code: String?) -> String {
    guard let code, !code.isEmpty else { return "Unknown" }
    return Locale.current.localizedString(forRegionCode: code.uppercased()) ?? code.uppercased()
}

private func countryLine(_ observation: IPObservation?) -> String {
    guard let observation else { return "Location unavailable" }
    let code = observation.countryLabel?.uppercased() ?? "—"
    return "\(countryName(code)) · \(code)"
}
