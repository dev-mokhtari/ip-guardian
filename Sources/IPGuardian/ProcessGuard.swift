import Darwin
import Foundation

struct ProcessActionReport: Sendable {
    let failedPIDs: Set<pid_t>

    var succeeded: Bool { failedPIDs.isEmpty }
}

struct ProcessRuntimeSnapshot: Sendable {
    let runningProcessCount: Int
    let pausedProcessCount: Int
    let states: [UUID: ProtectedAppsDisposition]
}

/// Owns the complete, lock-protected registry of processes paused by IPGuardian.
///
/// Every process fact is read directly from the kernel through `sysctl` and
/// `proc_pidinfo`. Reading the same facts by launching `/bin/ps` cost roughly
/// a hundred milliseconds per process-table read and repeated that several
/// times per second, which starved the enforcement loop it was meant to serve.
final class ProcessGuard: @unchecked Sendable {
    static let shared = ProcessGuard()

    private struct ProcessEntry {
        let pid: pid_t
        let parentPID: pid_t
        /// Resolved executable path, or nil for the few restricted system
        /// processes the kernel refuses to describe. Those entries stay in the
        /// table so the parent/child walk is never cut short around them.
        let executablePath: String?
    }

    private struct ProcessIdentity {
        let pid: pid_t
        /// Process creation time in microseconds. The previous `ps -o lstart=`
        /// token only resolved to whole seconds, so PID reuse inside a single
        /// second was invisible.
        let startTime: UInt64
        let executablePath: String
    }

    /// `SZOMB` from `sys/proc.h`. `kinfo_proc.kp_proc.p_stat` and
    /// `proc_bsdinfo.pbi_status` share these values.
    private static let zombieProcessStatus: Int32 = 5
    private static let executablePathCapacity = 4 * Int(MAXPATHLEN)

    private var pausedPIDs = Set<pid_t>()
    private var pausedIdentities: [pid_t: ProcessIdentity] = [:]

    private let guardianPID = getpid()
    private let stateLock = NSRecursiveLock()
    private lazy var failsafeRegistryURL = FileManager.default.temporaryDirectory
        .appendingPathComponent("ipguardian-\(guardianPID)-paused-pids", isDirectory: false)
    private var failsafeProcess: Process?
    /// Held open for the whole protected session. Its closure is what tells the
    /// helper that IPGuardian is gone, so nothing else may ever own a copy.
    private var failsafeLifeline: Pipe?
    private var lastPersistedRegistry: String?

    private init() {}

    /// Starts an independent helper that survives IPGuardian itself. If the
    /// app is force-quit or crashes while selected processes are stopped, the
    /// helper resumes the registered PIDs.
    @discardableResult
    func activateExitFailsafe() -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }

        guard persistPausedPIDs() else { return false }

        if let failsafeProcess, failsafeProcess.isRunning { return true }

        // The helper blocks on this pipe instead of polling `ps`. Closing the
        // write end is the death notification, so both ends are marked
        // close-on-exec: a copy inherited by any other child process would keep
        // the pipe open past IPGuardian's exit and silence the failsafe.
        let lifeline = Pipe()
        guard setCloseOnExec(lifeline.fileHandleForReading.fileDescriptor),
              setCloseOnExec(lifeline.fileHandleForWriting.fileDescriptor) else {
            return false
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = [
            "-c",
            Self.failsafeScript,
            "ipguardian-exit-failsafe",
            String(guardianPID),
            failsafeRegistryURL.path
        ]
        process.standardInput = lifeline.fileHandleForReading
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            failsafeProcess = process
            failsafeLifeline = lifeline
            return process.isRunning
        } catch {
            failsafeProcess = nil
            failsafeLifeline = nil
            return false
        }
    }

    /// Stops the independent helper after Protection has been deliberately
    /// turned off and every paused process has already been resumed.
    func deactivateExitFailsafe() {
        stateLock.lock()
        defer { stateLock.unlock() }
        // The registry is removed first, so a helper that wakes on either the
        // signal or the closed lifeline finds nothing left to resume.
        try? FileManager.default.removeItem(at: failsafeRegistryURL)
        lastPersistedRegistry = nil
        if let failsafeProcess, failsafeProcess.isRunning {
            failsafeProcess.terminate()
        }
        failsafeProcess = nil
        failsafeLifeline = nil
    }

    @discardableResult
    func pause(_ protectedApps: [ProtectedApp]) -> ProcessActionReport {
        stateLock.lock()
        defer { stateLock.unlock() }
        let discovered = matchingPIDs(for: protectedApps)
        pausedIdentities = Dictionary(uniqueKeysWithValues: pausedIdentities
            .filter { identityStillMatches($0.value) }
            .map { ($0.key, $0.value) })
        pausedPIDs = Set(pausedIdentities.keys)
        let newTargets = discovered.subtracting(pausedPIDs)
        var affected = Set<pid_t>()
        var failed = Set<pid_t>()

        for pid in newTargets where isSafeTarget(pid) {
            guard let identity = processIdentity(pid) else {
                if isRunningProcess(pid) { failed.insert(pid) }
                continue
            }
            pausedIdentities[pid] = identity
            pausedPIDs.insert(pid)
        }

        // The registry and helper must exist before SIGSTOP is sent so an
        // unexpected IPGuardian exit cannot strand a stopped application.
        guard activateExitFailsafe() else {
            for pid in newTargets {
                pausedIdentities.removeValue(forKey: pid)
                pausedPIDs.remove(pid)
                if isRunningProcess(pid) { failed.insert(pid) }
            }
            failed.formUnion(pausedPIDs)
            return ProcessActionReport(failedPIDs: failed)
        }

        for pid in newTargets where isSafeTarget(pid) {
            guard let identity = pausedIdentities[pid], identityStillMatches(identity) else {
                pausedIdentities.removeValue(forKey: pid)
                pausedPIDs.remove(pid)
                if isRunningProcess(pid) { failed.insert(pid) }
                continue
            }
            if Darwin.kill(pid, SIGSTOP) == 0 {
                affected.insert(pid)
            } else {
                pausedIdentities.removeValue(forKey: pid)
                pausedPIDs.remove(pid)
                if isRunningProcess(pid) { failed.insert(pid) }
            }
        }
        if !persistPausedPIDs() {
            for pid in affected where pausedIdentities[pid] != nil {
                if Darwin.kill(pid, SIGCONT) != 0, isRunningProcess(pid) {
                    failed.insert(pid)
                }
                pausedIdentities.removeValue(forKey: pid)
                pausedPIDs.remove(pid)
            }
        }
        return ProcessActionReport(failedPIDs: failed)
    }

    @discardableResult
    func resumeAll() -> ProcessActionReport {
        stateLock.lock()
        defer { stateLock.unlock() }
        let targets = pausedIdentities.values
        var failed = Set<pid_t>()
        for identity in targets {
            // The signal is always attempted, even when identity verification
            // is momentarily unavailable. A stray SIGCONT lands on a process
            // that is already running and does nothing; skipping one leaves a
            // stopped application frozen for good.
            guard Darwin.kill(identity.pid, SIGCONT) != 0 else { continue }
            if identityStillMatches(identity) {
                failed.insert(identity.pid)
            }
        }
        pausedIdentities = Dictionary(uniqueKeysWithValues: pausedIdentities
            .filter { failed.contains($0.key) }
            .map { ($0.key, $0.value) })
        pausedPIDs = Set(pausedIdentities.keys)
        if !persistPausedPIDs() { failed.formUnion(pausedPIDs) }
        return ProcessActionReport(failedPIDs: failed)
    }

    /// Closes every selected process while it is still stopped. SIGCONT is
    /// deliberately never sent on this path.
    @discardableResult
    func terminateAll(_ protectedApps: [ProtectedApp]) -> ProcessActionReport {
        stateLock.lock()
        defer { stateLock.unlock() }
        let discovered = matchingPIDs(for: protectedApps)
        for pid in discovered where pausedIdentities[pid] == nil {
            if let identity = processIdentity(pid) { pausedIdentities[pid] = identity }
        }
        pausedPIDs = Set(pausedIdentities.keys)
        guard activateExitFailsafe() else {
            return ProcessActionReport(
                failedPIDs: Set(discovered.filter(isRunningProcess))
            )
        }
        let targets = pausedIdentities.values.filter(identityStillMatches)
        var failed = Set(discovered.subtracting(Set(targets.map(\.pid))))

        for identity in targets {
            if Darwin.kill(identity.pid, SIGSTOP) != 0 { failed.insert(identity.pid) }
        }
        for identity in targets where identityStillMatches(identity) {
            if Darwin.kill(identity.pid, SIGKILL) == 0 {
                failed.remove(identity.pid)
            } else {
                failed.insert(identity.pid)
            }
        }

        // A helper may be spawned while its parent is being killed. Re-scan
        // once and terminate any remaining selected descendants.
        let remaining = matchingPIDs(for: protectedApps)
        for pid in remaining where isSafeTarget(pid) && isAlive(pid) {
            guard let identity = processIdentity(pid), identityStillMatches(identity) else {
                failed.insert(pid)
                continue
            }
            pausedIdentities[pid] = identity
            pausedPIDs.insert(pid)
            guard activateExitFailsafe() else {
                pausedIdentities.removeValue(forKey: pid)
                pausedPIDs.remove(pid)
                failed.insert(pid)
                continue
            }
            if Darwin.kill(pid, SIGSTOP) != 0, isRunningProcess(pid) {
                failed.insert(pid)
                continue
            }
            if Darwin.kill(pid, SIGKILL) == 0 {
                failed.remove(pid)
            } else {
                failed.insert(pid)
            }
        }
        let deadline = Date().addingTimeInterval(1.2)
        while Date() < deadline {
            let remaining = pausedIdentities.values.filter(identityStillMatches)
            if remaining.isEmpty { break }
            usleep(60_000)
        }
        let survivors = Set(matchingPIDs(for: protectedApps).filter(isRunningProcess))
        failed = survivors
        pausedIdentities = Dictionary(uniqueKeysWithValues: pausedIdentities
            .filter { survivors.contains($0.key) && identityStillMatches($0.value) }
            .map { ($0.key, $0.value) })
        pausedPIDs = Set(pausedIdentities.keys)
        if !persistPausedPIDs() { failed.formUnion(pausedPIDs) }
        return ProcessActionReport(failedPIDs: failed)
    }

    @discardableResult
    func terminateNewMatches(_ protectedApps: [ProtectedApp]) -> ProcessActionReport {
        stateLock.lock()
        defer { stateLock.unlock() }
        let targets = matchingPIDs(for: protectedApps)
        var failed = Set<pid_t>()
        for pid in targets where isSafeTarget(pid) {
            guard let identity = processIdentity(pid), identityStillMatches(identity) else {
                if isRunningProcess(pid) { failed.insert(pid) }
                continue
            }
            pausedIdentities[pid] = identity
            pausedPIDs.insert(pid)
            guard activateExitFailsafe() else {
                pausedIdentities.removeValue(forKey: pid)
                pausedPIDs.remove(pid)
                failed.insert(pid)
                continue
            }
            if Darwin.kill(pid, SIGSTOP) != 0, isRunningProcess(pid) {
                failed.insert(pid)
                continue
            }
            if Darwin.kill(pid, SIGKILL) != 0 {
                if isRunningProcess(pid) { failed.insert(pid) }
            }
        }
        for pid in targets where !failed.contains(pid) {
            pausedIdentities.removeValue(forKey: pid)
        }
        pausedPIDs = Set(pausedIdentities.keys)
        if !persistPausedPIDs() { failed.formUnion(pausedPIDs) }
        return ProcessActionReport(failedPIDs: failed)
    }

    func runtimeSnapshot(
        for protectedApps: [ProtectedApp],
        protectionActive: Bool
    ) -> ProcessRuntimeSnapshot {
        stateLock.lock()
        defer { stateLock.unlock() }

        pausedIdentities = Dictionary(uniqueKeysWithValues: pausedIdentities
            .filter { identityStillMatches($0.value) }
            .map { ($0.key, $0.value) })
        pausedPIDs = Set(pausedIdentities.keys)

        let table = processTable()
        var allMatches = Set<pid_t>()
        let states = Dictionary(uniqueKeysWithValues: protectedApps.map { app in
            let matches = matchingPIDs(for: [app], using: table)
            allMatches.formUnion(matches)
            let state: ProtectedAppsDisposition
            if matches.isEmpty {
                state = .closed
            } else if !protectionActive {
                state = .notProtected
            } else if matches.allSatisfy({ pausedPIDs.contains($0) }) {
                state = .paused
            } else {
                state = .running
            }
            return (app.id, state)
        })
        return ProcessRuntimeSnapshot(
            runningProcessCount: allMatches.count,
            pausedProcessCount: allMatches.intersection(pausedPIDs).count,
            states: states
        )
    }

    func isProtectedApplication(
        bundleIdentifier: String?,
        bundlePath: String?,
        protectedApps: [ProtectedApp]
    ) -> Bool {
        guard let bundlePath else { return false }
        let standardizedPath = URL(fileURLWithPath: bundlePath).standardizedFileURL.path
        return protectedApps.contains { app in
            guard standardizedAppPath(app) == standardizedPath else { return false }
            guard let selectedIdentifier = app.bundleIdentifier else { return true }
            return bundleIdentifier == selectedIdentifier
        }
    }

    private func matchingPIDs(
        for protectedApps: [ProtectedApp],
        using suppliedTable: [ProcessEntry]? = nil
    ) -> Set<pid_t> {
        guard !protectedApps.isEmpty else { return [] }

        let table = suppliedTable ?? processTable()
        var roots = Set<pid_t>()

        let appPaths = bundlePathVariants(for: protectedApps)
        for entry in table {
            guard let command = entry.executablePath else { continue }
            if appPaths.contains(where: { path in
                command == path || command.hasPrefix(path + "/Contents/")
            }) {
                roots.insert(entry.pid)
            }
        }

        let childrenByParent = Dictionary(grouping: table, by: \.parentPID)
        var result = roots
        var queue = Array(roots)

        while let parent = queue.popLast() {
            for child in childrenByParent[parent] ?? [] where !result.contains(child.pid) {
                result.insert(child.pid)
                queue.append(child.pid)
            }
        }

        return result.filter(isSafeTarget)
    }

    /// The kernel reports the real executable path, while Foundation both
    /// resolves symlinks and strips the `/private` prefix from a selected
    /// bundle path. Every plausible spelling is matched, so an app reached
    /// through a symlinked folder — or running translocated from
    /// `/private/var/folders/…` — is still recognised.
    private func bundlePathVariants(for protectedApps: [ProtectedApp]) -> [String] {
        var values: [String] = []
        for app in protectedApps {
            let url = URL(fileURLWithPath: app.path)
            let spellings = [
                app.path,
                url.standardizedFileURL.path,
                url.resolvingSymlinksInPath().path
            ]
            for spelling in spellings {
                for variant in privatePrefixVariants(of: spelling)
                where !values.contains(variant) {
                    values.append(variant)
                }
            }
        }
        return values
    }

    /// Directories that physically live under `/private` and are reached
    /// through a symlink at the root of the filesystem.
    private static let privateRoots = ["/tmp", "/var", "/etc"]

    private func privatePrefixVariants(of path: String) -> [String] {
        guard !path.isEmpty else { return [] }
        if path.hasPrefix("/private/") {
            return [path, String(path.dropFirst("/private".count))]
        }
        if Self.privateRoots.contains(where: { path == $0 || path.hasPrefix($0 + "/") }) {
            return [path, "/private" + path]
        }
        return [path]
    }

    private func processTable() -> [ProcessEntry] {
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0]
        let stride = MemoryLayout<kinfo_proc>.stride

        // The table can grow between the sizing call and the read, so ask for
        // headroom and retry instead of returning a truncated snapshot.
        for attempt in 0..<4 {
            var probeSize = 0
            guard sysctl(&mib, 4, nil, &probeSize, nil, 0) == 0, probeSize > 0 else {
                return []
            }
            let capacity = probeSize / stride + 64 * (attempt + 1)
            var buffer = [kinfo_proc](repeating: kinfo_proc(), count: capacity)
            var readSize = capacity * stride
            if sysctl(&mib, 4, &buffer, &readSize, nil, 0) == 0 {
                return buffer.prefix(readSize / stride).compactMap(entry(from:))
            }
            guard errno == ENOMEM else { return [] }
        }
        return []
    }

    private func entry(from record: kinfo_proc) -> ProcessEntry? {
        let pid = record.kp_proc.p_pid
        guard pid > 0,
              Int32(record.kp_proc.p_stat) != Self.zombieProcessStatus else { return nil }
        return ProcessEntry(
            pid: pid,
            parentPID: record.kp_eproc.e_ppid,
            executablePath: executablePath(pid)
        )
    }

    private func standardizedAppPath(_ app: ProtectedApp) -> String {
        URL(fileURLWithPath: app.path).standardizedFileURL.path
    }

    private func executablePath(_ pid: pid_t) -> String? {
        var buffer = [CChar](repeating: 0, count: Self.executablePathCapacity)
        guard proc_pidpath(pid, &buffer, UInt32(buffer.count)) > 0 else { return nil }
        let path = String(cString: buffer)
        return path.isEmpty ? nil : path
    }

    private func bsdInfo(_ pid: pid_t) -> proc_bsdinfo? {
        var info = proc_bsdinfo()
        let size = Int32(MemoryLayout<proc_bsdinfo>.size)
        guard proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size else { return nil }
        return info
    }

    private func startTime(_ info: proc_bsdinfo) -> UInt64 {
        UInt64(info.pbi_start_tvsec) * 1_000_000 + UInt64(info.pbi_start_tvusec)
    }

    private func processIdentity(_ pid: pid_t) -> ProcessIdentity? {
        guard isSafeTarget(pid),
              let info = bsdInfo(pid),
              let path = executablePath(pid) else { return nil }
        return ProcessIdentity(
            pid: pid,
            startTime: startTime(info),
            executablePath: path
        )
    }

    private func identityStillMatches(_ identity: ProcessIdentity) -> Bool {
        guard isAlive(identity.pid),
              let info = bsdInfo(identity.pid),
              Int32(info.pbi_status) != Self.zombieProcessStatus,
              let path = executablePath(identity.pid) else { return false }
        return startTime(info) == identity.startTime
            && path == identity.executablePath
    }

    private func isRunningProcess(_ pid: pid_t) -> Bool {
        guard isAlive(pid) else { return false }
        guard let info = bsdInfo(pid) else { return true }
        return Int32(info.pbi_status) != Self.zombieProcessStatus
    }

    private func setCloseOnExec(_ descriptor: Int32) -> Bool {
        let flags = fcntl(descriptor, F_GETFD)
        guard flags != -1 else { return false }
        return fcntl(descriptor, F_SETFD, flags | FD_CLOEXEC) != -1
    }

    @discardableResult
    private func persistPausedPIDs() -> Bool {
        let records = pausedIdentities.values
            .filter(identityStillMatches)
            .sorted { $0.pid < $1.pid }
            .map { "\($0.pid)\t\(registryPath(for: $0))" }

        guard !records.isEmpty else {
            lastPersistedRegistry = nil
            do {
                if FileManager.default.fileExists(atPath: failsafeRegistryURL.path) {
                    try FileManager.default.removeItem(at: failsafeRegistryURL)
                }
                return true
            } catch {
                return false
            }
        }

        let contents = records.joined(separator: "\n") + "\n"
        if contents == lastPersistedRegistry,
           FileManager.default.fileExists(atPath: failsafeRegistryURL.path) {
            return true
        }
        do {
            try contents.write(
                to: failsafeRegistryURL,
                atomically: true,
                encoding: .utf8
            )
            lastPersistedRegistry = contents
            return true
        } catch {
            lastPersistedRegistry = nil
            return false
        }
    }

    /// A newline inside a path would split one registry record into two. Such a
    /// path is written empty, which tells the helper to resume without the
    /// optional identity check rather than to skip the process entirely.
    private func registryPath(for identity: ProcessIdentity) -> String {
        identity.executablePath.contains(where: \.isNewline)
            ? ""
            : identity.executablePath
    }

    private static let failsafeScript = #"""
parent_pid="$1"
registry="$2"

# Standard input is a pipe whose write end only IPGuardian holds. This read
# returns the moment that process disappears, so the helper costs nothing at
# all while IPGuardian is healthy.
read -r _ 2>/dev/null || true

# Defence in depth: an unexpected end-of-file must never resume protected apps
# while IPGuardian is still running.
while /bin/kill -0 "$parent_pid" 2>/dev/null; do
    /bin/sleep 0.2
done

if [ -f "$registry" ]; then
    tab="$(/usr/bin/printf '\t')"
    while IFS="$tab" read -r target_pid target_path; do
        case "$target_pid" in
            ''|*[!0-9]*) continue ;;
        esac
        if [ "$target_pid" -gt 1 ]; then
            if [ -n "$target_path" ]; then
                current_path="$(/bin/ps -p "$target_pid" -o comm= 2>/dev/null)"
                while [ "${current_path# }" != "$current_path" ]; do
                    current_path="${current_path# }"
                done
                # An unreadable result must not strand a stopped process: a
                # stray SIGCONT is harmless, a frozen application is not.
                if [ -n "$current_path" ] && [ "$current_path" != "$target_path" ]; then
                    continue
                fi
            fi
            /bin/kill -CONT "$target_pid" 2>/dev/null || true
        fi
    done < "$registry"
    /bin/rm -f "$registry"
fi

"""#

    private func isSafeTarget(_ pid: pid_t) -> Bool {
        pid > 1 && pid != getpid()
    }

    private func isAlive(_ pid: pid_t) -> Bool {
        isSafeTarget(pid) && Darwin.kill(pid, 0) == 0
    }
}
