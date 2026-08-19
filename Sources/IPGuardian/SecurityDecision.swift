import Foundation

enum ConnectionDecision: Equatable {
    case safe
    case unsafe([String])
}

enum SecurityDecision {
    static func evaluate(
        baseline: IPObservation,
        current: IPObservation,
        policy: IPChangePolicy,
        allowedCountries: [String] = []
    ) -> ConnectionDecision {
        var reasons: [String] = []

        let trustedRoute = baseline.routeSignature ?? "direct/system-default"
        let currentRoute = current.routeSignature ?? "direct/system-default"
        if trustedRoute != currentRoute {
            reasons.append(
                "Route changed from \(baseline.proxySummary ?? trustedRoute) to \(current.proxySummary ?? currentRoute)."
            )
        }

        let currentCountry = CountryCode.normalized(current.countryLabel)

        switch policy {
        case .exactIP:
            if baseline.ipv4 != current.ipv4 {
                reasons.append("Public IPv4 changed from \(baseline.ipv4) to \(current.ipv4).")
            }
        case .sameCountry:
            // The allowed list decides, not the baseline: moving between the
            // countries the user permitted is the point of the policy.
            if !AllowedCountries.allows(currentCountry, in: allowedCountries) {
                reasons.append(
                    "The connection is in \(currentCountry ?? "an unknown country"), which is not in the allowed list."
                )
            }
        }

        if current.ipv6LeakStatus == .leakDetected {
            let suffix = current.directIPv6.map { ": \($0)" } ?? "."
            reasons.append("A direct IPv6 path bypassed the protected route\(suffix)")
        }

        if !isProxyRoute(currentRoute),
           ipv6Identity(baseline.ipv6) != ipv6Identity(current.ipv6) {
            let before = baseline.ipv6 ?? "none"
            let after = current.ipv6 ?? "none"
            reasons.append("Public IPv6 network changed from \(before) to \(after).")
        }

        return reasons.isEmpty ? .safe : .unsafe(reasons)
    }

    /// Compares IPv6 by network prefix, so a routine privacy-address rotation
    /// inside the same /64 is not mistaken for a new connection. An address the
    /// system cannot parse falls back to its literal text, which keeps the
    /// comparison no weaker than a plain string match.
    static func ipv6Identity(_ value: String?) -> String? {
        guard let value else { return nil }
        return IPv6Prefix.network(value) ?? value.lowercased()
    }

    private static func isProxyRoute(_ signature: String) -> Bool {
        if signature.hasPrefix("proxy:") {
            return !signature.hasPrefix("proxy:direct/system-default|")
        }
        return signature != "direct/system-default"
    }
}

struct ChangeCandidateFingerprint: Hashable {
    let ipv4: String?
    let ipv6: String?
    let directIPv6: String?
    let country: String?
    let route: String
    let leakStatus: IPv6LeakStatus

    init(_ observation: IPObservation, policy: IPChangePolicy) {
        ipv4 = policy == .exactIP ? observation.ipv4 : nil
        // Networks, not whole addresses: a rotating privacy address must not
        // make consecutive confirmation checks look like different candidates.
        ipv6 = SecurityDecision.ipv6Identity(observation.ipv6)
        directIPv6 = SecurityDecision.ipv6Identity(observation.directIPv6)
        // Each policy's fingerprint holds only what that policy decides on.
        // Under Exact IP the country is a label nobody verified, so letting it
        // vary would make consecutive confirmation checks disagree about a
        // candidate that never actually changed.
        country = policy == .sameCountry ? observation.countryLabel?.uppercased() : nil
        route = observation.routeSignature ?? "direct/system-default"
        leakStatus = observation.ipv6LeakStatus
    }
}

struct ChangeConfirmationTracker {
    static let requiredSightings = 3

    private(set) var fingerprint: ChangeCandidateFingerprint?
    private(set) var sightings = 0

    var isConfirmed: Bool { sightings >= Self.requiredSightings }
    var completedConfirmationChecks: Int { max(0, sightings - 1) }

    mutating func register(
        _ observation: IPObservation,
        policy: IPChangePolicy
    ) -> Bool {
        let newFingerprint = ChangeCandidateFingerprint(observation, policy: policy)
        if fingerprint == newFingerprint {
            sightings += 1
        } else {
            fingerprint = newFingerprint
            sightings = 1
        }
        return isConfirmed
    }

    mutating func reset() {
        fingerprint = nil
        sightings = 0
    }
}
