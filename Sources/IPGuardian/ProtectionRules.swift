import Foundation

/// Decides whether Protection is allowed to start.
///
/// The rule lives outside the controller so it can be exercised without a
/// running app, a process table, or a live network route.
enum ProtectionReadiness {
    /// The reason Protection cannot start yet, or nil when it can.
    static func requirement(
        protectedAppCount: Int,
        runningProcessCount: Int,
        proxyConfigurationIncomplete: Bool,
        needsAllowedCountries: Bool = false
    ) -> String? {
        if protectedAppCount == 0 {
            return "Add at least one application to enable Protection."
        }
        if needsAllowedCountries {
            return "Choose up to \(AllowedCountries.maximumCount) allowed countries and save them before starting Protection."
        }
        if runningProcessCount > 0 {
            return "Close all protected applications before starting Protection."
        }
        if proxyConfigurationIncomplete {
            return "Complete the enabled Proxy configuration before starting Protection."
        }
        return nil
    }

    /// Derived from `requirement` rather than repeating the conditions, so the
    /// button state and the explanation under it can never disagree.
    static func canStart(
        protectedAppCount: Int,
        runningProcessCount: Int,
        proxyConfigurationIncomplete: Bool,
        needsAllowedCountries: Bool = false
    ) -> Bool {
        requirement(
            protectedAppCount: protectedAppCount,
            runningProcessCount: runningProcessCount,
            proxyConfigurationIncomplete: proxyConfigurationIncomplete,
            needsAllowedCountries: needsAllowedCountries
        ) == nil
    }
}

/// The countries Same Country will accept.
///
/// A list rather than one country, because a VPN left on automatic moves
/// between servers and a rotating proxy answers from several exits at once.
/// The cap keeps the promise meaningful: three countries is a choice, thirty
/// would be no rule at all.
enum AllowedCountries {
    static let maximumCount = 3

    /// Uppercased, de-duplicated, invalid codes dropped, capped.
    static func normalized(_ codes: [String]) -> [String] {
        var seen = Set<String>()
        var result: [String] = []
        for code in codes {
            guard let normalized = CountryCode.resolved(code),
                  !seen.contains(normalized) else { continue }
            seen.insert(normalized)
            result.append(normalized)
            if result.count == maximumCount { break }
        }
        return result
    }

    static func isComplete(_ codes: [String]) -> Bool {
        let normalized = normalized(codes)
        return !normalized.isEmpty && normalized.count <= maximumCount
    }

    static func allows(_ country: String?, in codes: [String]) -> Bool {
        guard let country = CountryCode.resolved(country) else { return false }
        return normalized(codes).contains(country)
    }
}

/// What the country votes are allowed to conclude.
///
/// Two questions, deliberately kept apart. Agreement decides whether the
/// country is known at all; the allowed list decides whether that country is
/// acceptable, and that second judgement belongs to `SecurityDecision` so the
/// usual confirmation checks run before anything is closed.
enum CountryVerdict: Equatable {
    /// The country is settled. Whether it is permitted is decided later.
    case confirmed(String)
    /// Sources disagree in a way the allowed list cannot excuse.
    case conflicting([String])
    /// Nothing reached two agreeing sources.
    case insufficient

    static func evaluate(
        votes: [String],
        allowedCountries: [String],
        minimumAgreement: Int = 2
    ) -> CountryVerdict {
        let valid = votes.compactMap { CountryCode.resolved($0) }
        guard !valid.isEmpty else { return .insufficient }

        let allowed = AllowedCountries.normalized(allowedCountries)
        let distinct = Set(valid)

        // Everything outside the list is only tolerated when every source says
        // the same thing: that is a connection genuinely sitting in a country
        // the user did not permit, and it has to reach the decision layer to be
        // confirmed and acted on. A mixture is simply not trustworthy.
        let outside = distinct.subtracting(allowed)
        if !outside.isEmpty {
            guard distinct.count == 1, let only = distinct.first else {
                return .conflicting(distinct.sorted())
            }
            return .confirmed(only)
        }

        // Inside the list, sources naming different permitted countries do not
        // conflict — that is what listing several of them means.
        let counts = Dictionary(grouping: valid, by: { $0 }).mapValues(\.count)
        let ranked = counts.sorted {
            $0.value != $1.value ? $0.value > $1.value : $0.key < $1.key
        }
        guard let winner = ranked.first, winner.value >= minimumAgreement else {
            return .insufficient
        }
        return .confirmed(winner.key)
    }
}

enum ProtectionShutdown {
    /// Whether Protection can be switched off while protected applications stay
    /// open.
    ///
    /// Only a connection that is verified at that very moment earns this. In
    /// every other state IPGuardian cannot vouch for what those applications
    /// would talk to next, so they have to be closed first. Deliberately
    /// finishing a session is the common case, and it must not cost the user
    /// their unsaved work.
    static func mayLeaveApplicationsRunning(mode: GuardianMode) -> Bool {
        mode == .protected
    }
}

enum ProtectedAppTally {
    /// Applications that currently have a process, whether it is running or
    /// paused. A closed application is not something the user has to deal with.
    static func activeCount(states: [ProtectedAppsDisposition]) -> Int {
        states.reduce(into: 0) { count, state in
            switch state {
            case .running, .paused: count += 1
            case .notProtected, .closed: break
            }
        }
    }
}

/// Names the parts of the connection that differ from the trusted baseline.
///
/// Presentation only: `SecurityDecision` decides what is actually unsafe. The
/// two must agree on what counts as a change, or the interface explains a
/// verdict the engine never reached.
enum ConnectionChangeSummary {
    static func changedFields(
        baseline: IPObservation,
        candidate: IPObservation,
        policy: IPChangePolicy
    ) -> [String] {
        var values: [String] = []

        if policy == .exactIP, baseline.ipv4 != candidate.ipv4 {
            values.append("Public IPv4")
        }
        if CountryCode.normalized(baseline.countryLabel)
            != CountryCode.normalized(candidate.countryLabel) {
            values.append("Country")
        }
        if (baseline.routeSignature ?? "direct/system-default")
            != (candidate.routeSignature ?? "direct/system-default") {
            values.append("Route")
        }
        // Networks, not whole addresses, exactly as the decision compares them.
        if SecurityDecision.ipv6Identity(baseline.ipv6)
            != SecurityDecision.ipv6Identity(candidate.ipv6) {
            values.append("IPv6")
        }
        if candidate.ipv6LeakStatus == .leakDetected {
            values.append("IPv6 leak")
        }

        return values
    }
}
