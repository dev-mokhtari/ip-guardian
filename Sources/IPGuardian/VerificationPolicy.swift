import Foundation

/// Counts only completed automatic retries. The first failed verification is
/// the incident that starts retrying and is deliberately not counted as retry 1.
struct RetryFailureTracker: Equatable {
    let maximumRetries: Int
    private(set) var completedRetries = 0

    init(maximumRetries: Int = 3) {
        self.maximumRetries = max(1, maximumRetries)
    }

    mutating func recordFailedRetry() -> Bool {
        completedRetries = min(maximumRetries, completedRetries + 1)
        return completedRetries >= maximumRetries
    }

    mutating func reset() {
        completedRetries = 0
    }
}

/// Selects a stable public IP by agreement instead of requiring every healthy
/// provider to respond. A single outlier must not invalidate two matching
/// responses from the independent provider pool.
enum IPConsensus {
    static func selectIP(
        from values: [String],
        minimumAgreement: Int
    ) -> String? {
        guard !values.isEmpty else { return nil }
        let counts = Dictionary(grouping: values, by: { $0 }).mapValues(\.count)
        let ranked = counts.sorted {
            if $0.value != $1.value { return $0.value > $1.value }
            return $0.key < $1.key
        }

        guard let winner = ranked.first,
              winner.value >= minimumAgreement else { return nil }
        guard ranked.dropFirst().first?.value != winner.value else { return nil }
        return winner.key
    }
}

/// Picks the most reported country, used only to label a connection under
/// Exact IP. Whether a country is acceptable is `CountryVerdict`'s question.
enum CountryConsensus {
    static func selectCountry(
        from values: [String],
        minimumAgreement: Int
    ) -> String? {
        let normalized = values.compactMap { value -> String? in
            let code = value.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
            return code.range(of: "^[A-Z]{2}$", options: .regularExpression) == nil
                ? nil
                : code
        }
        guard !normalized.isEmpty else { return nil }

        let counts = Dictionary(grouping: normalized, by: { $0 }).mapValues(\.count)
        let ranked = counts.sorted {
            if $0.value != $1.value { return $0.value > $1.value }
            return $0.key < $1.key
        }
        guard let winner = ranked.first,
              winner.value >= minimumAgreement else { return nil }
        guard ranked.dropFirst().first?.value != winner.value else { return nil }
        return winner.key
    }
}

/// What Same Country falls back to when the country cannot be settled.
///
/// Geo-IP databases routinely disagree about datacentre addresses, which is
/// what every VPN exit is. Treating that as a failure made the relaxed policy
/// stricter than the strict one: Exact IP looks at the same moment, sees the
/// trusted address unchanged, and is satisfied. So Same Country uses that same
/// rule as its floor, and can never be worse than Exact IP.
enum TrustedAddressFallback {
    /// True when the observed address is the one the trusted baseline was built
    /// on. The address must still have come from provider consensus; a single
    /// provider claiming it is not enough.
    static func acceptsUnchangedAddress(
        consensusIPv4: String?,
        knownIPv4: String?
    ) -> Bool {
        guard let consensusIPv4, let knownIPv4, !knownIPv4.isEmpty else { return false }
        return consensusIPv4 == knownIPv4
    }
}
