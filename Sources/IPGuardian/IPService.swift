import Darwin
import Foundation

private struct IPifyResponse: Decodable {
    let ip: String
}

private struct CloudflareMetaResponse: Decodable {
    let clientIp: String
    let country: String?
}

private struct CountryIsResponse: Decodable {
    let ip: String
    let country: String
}

private struct IPWhoResponse: Decodable {
    let success: Bool?
    let country_code: String?
}

private struct ProviderIPv4: Sendable {
    let ip: String
    let provider: String
    let country: String?
}

private struct ProviderAttempt: Sendable {
    let provider: String
    let value: ProviderIPv4?
    let timedOut: Bool
    let errorMessage: String?

    var summary: String {
        if let value {
            let country = value.country.map { " (\($0))" } ?? ""
            return "\(provider): \(value.ip)\(country)"
        }
        if timedOut { return "\(provider): timed out" }
        return "\(provider): \(errorMessage ?? "failed")"
    }
}

private struct IPv4ConsensusResult: Sendable {
    let ip: String
    let agreeingResults: [ProviderIPv4]
}

private struct ConnectionVerificationResult: Sendable {
    let ip: String
    let country: String?
}

private struct CountryVote: Sendable {
    let provider: String
    let country: String?
    let errorMessage: String?

    var summary: String {
        if let country { return "\(provider): \(country)" }
        return "\(provider): \(errorMessage ?? "failed")"
    }
}

private struct IPv6Inspection: Sendable {
    let publicIPv6: String?
    let directIPv6: String?
    let leakStatus: IPv6LeakStatus
}

private final class CurlProcessBox: @unchecked Sendable {
    private let lock = NSLock()
    private var process: Process?
    private var cancelled = false

    func attach(_ process: Process) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !cancelled else { return false }
        self.process = process
        return true
    }

    func detach(_ process: Process) {
        lock.lock()
        defer { lock.unlock() }
        if self.process === process { self.process = nil }
    }

    func cancel() {
        lock.lock()
        cancelled = true
        let process = self.process
        lock.unlock()
        if process?.isRunning == true { process?.terminate() }
    }
}

enum IPServiceError: LocalizedError, Sendable {
    case networkUnavailable
    case timedOut
    case noProviderResponded(String)
    case insufficientProviderConsensus(successful: Int, total: Int, details: String)
    case providerDisagreement([String], String)
    case insufficientCountryConsensus(String)
    case countryDisagreement([String], String)
    case invalidResponse(String)
    case ipv6VerificationFailed
    case routeChangedDuringVerification
    case proxyCommandFailed(String)
    /// A `curl` probe that exited non-zero. The status is kept because it
    /// distinguishes "the request never left this machine" from "something
    /// went wrong", which decides whether a missing IPv6 answer proves that no
    /// IPv6 path exists.
    case probeFailed(status: Int32, detail: String)
    /// The provider answered 429. Unlike a transient failure this is the server
    /// asking to be left alone, and it is the only signal that starts a cooldown.
    case rateLimited(String)

    var errorDescription: String? {
        switch self {
        case .networkUnavailable:
            return "Network connection is unavailable."
        case .timedOut:
            return "IP verification request timed out."
        case .noProviderResponded(let details):
            return "IP verification services are not responding. \(details)"
        case .insufficientProviderConsensus(let successful, let total, let details):
            return "Only \(successful) of \(total) IPv4 providers responded successfully; two matching providers are required. \(details)"
        case .providerDisagreement(let values, let details):
            return "Providers returned conflicting results: \(values.joined(separator: ", ")). \(details)"
        case .insufficientCountryConsensus(let details):
            return "The country could not be confirmed by the required number of independent sources. \(details)"
        case .countryDisagreement(let values, let details):
            return "Country sources returned conflicting results: \(values.joined(separator: ", ")). \(details)"
        case .invalidResponse(let provider):
            return "Connection information from \(provider) is incomplete."
        case .ipv6VerificationFailed:
            return "IPv6 verification could not be completed."
        case .routeChangedDuringVerification:
            return "The network route changed while the connection was being verified."
        case .proxyCommandFailed(let details):
            return "The active proxy route could not be verified: \(details)"
        case .probeFailed(let status, let detail):
            return "A connection probe failed with status \(status). \(detail)"
        case .rateLimited(let provider):
            return "\(provider) is rate limiting IP Guardian."
        }
    }

    var userFacingDescription: String {
        switch self {
        case .networkUnavailable:
            return "The network connection is unavailable."
        case .timedOut,
             .noProviderResponded(_),
             .insufficientProviderConsensus(_, _, _):
            return "Connection verification is temporarily unavailable."
        case .providerDisagreement(_, _):
            return "Different public IP addresses were detected. Exact IP verification could not be completed."
        case .insufficientCountryConsensus(_):
            return "Country verification is temporarily unavailable."
        case .countryDisagreement(_, _):
            // The route is read locally and was never in doubt; naming it here
            // sent the user looking in the wrong place.
            return "Location services reported different countries, so the country could not be confirmed."
        case .invalidResponse(_):
            return "Connection verification returned incomplete information."
        case .ipv6VerificationFailed:
            return "IPv6 verification is temporarily unavailable."
        case .routeChangedDuringVerification:
            return "The network route changed while the connection was being verified."
        case .proxyCommandFailed(_):
            return "The active Proxy route could not be verified."
        case .probeFailed(_, _):
            return "IPv6 verification is temporarily unavailable."
        case .rateLimited(_):
            return "Country verification is temporarily unavailable."
        }
    }
}

/// Tracks which providers have asked to be left alone, and for how long.
actor ProviderCooldown {
    private var blockedUntil: [String: Date] = [:]
    private var consecutiveLimits: [String: Int] = [:]

    private let firstDelay: TimeInterval
    private let maximumDelay: TimeInterval

    init(firstDelay: TimeInterval = 120, maximumDelay: TimeInterval = 900) {
        self.firstDelay = firstDelay
        self.maximumDelay = maximumDelay
    }

    func isResting(_ provider: String, now: Date = Date()) -> Bool {
        guard let until = blockedUntil[provider] else { return false }
        return now < until
    }

    func recordSuccess(_ provider: String) {
        blockedUntil[provider] = nil
        consecutiveLimits[provider] = nil
    }

    /// Each repeated 429 doubles the rest, so a provider that keeps refusing is
    /// asked less and less often instead of being polled forever.
    func recordRateLimit(_ provider: String, now: Date = Date()) -> Date {
        let limits = (consecutiveLimits[provider] ?? 0) + 1
        consecutiveLimits[provider] = limits
        let delay = min(maximumDelay, firstDelay * pow(2, Double(limits - 1)))
        let until = now.addingTimeInterval(delay)
        blockedUntil[provider] = until
        return until
    }
}

enum IPService {
    private static let primaryProviderTimeout: TimeInterval = 5
    private static let secondaryProviderTimeout: TimeInterval = 4
    private static let ipv6Timeout: TimeInterval = 4
    private static let countryTimeout: TimeInterval = 5
    private static let minimumIPv4Agreement = 2
    private static let minimumCountryAgreement = 2

    /// Country fallbacks are free public services with tight quotas, and the
    /// protected cadence can reach them hundreds of times an hour. A provider
    /// that answers 429 is rested instead of being asked again immediately,
    /// which is what turns a temporary quota into a permanent verification
    /// failure. Only an explicit 429 starts a cooldown: a transient network
    /// error must stay instantly retryable so it cannot outlast a retry cycle.
    private static let countryProviderCooldown = ProviderCooldown()

    static func currentProxyState() -> SystemProxyState {
        SystemProxyReader.current()
    }

    static func currentRouteIdentity() -> NetworkRouteIdentity {
        let proxy = currentProxyState()
        return NetworkRouteReader.current(proxy: proxy)
    }

    static func fetchOverview(
        policy: IPChangePolicy,
        allowedCountries: [String] = []
    ) async throws -> IPObservation {
        try await fetchVerifiedObservation(
            policy: policy,
            allowedCountries: allowedCountries,
            knownIPv4: nil,
            knownCountry: nil,
            toleratesIPv6Failure: true
        )
    }

    static func fetchProtectionObservation(
        policy: IPChangePolicy,
        allowedCountries: [String] = [],
        knownIPv4: String? = nil,
        knownCountry: String? = nil
    ) async throws -> IPObservation {
        try await fetchVerifiedObservation(
            policy: policy,
            allowedCountries: allowedCountries,
            knownIPv4: knownIPv4,
            knownCountry: knownCountry,
            toleratesIPv6Failure: false
        )
    }

    private static func fetchVerifiedObservation(
        policy: IPChangePolicy,
        allowedCountries: [String],
        knownIPv4: String?,
        knownCountry: String?,
        toleratesIPv6Failure: Bool
    ) async throws -> IPObservation {
        let proxy = currentProxyState()
        let route = NetworkRouteReader.current(proxy: proxy)
        async let ipv6Task = inspectIPv6(proxy: proxy, route: route)

        let verification: ConnectionVerificationResult
        switch policy {
        case .exactIP:
            // Exact IP decides on the address alone. The country is never
            // verified here and can never fail the check: it is a label, taken
            // only from what the address providers already returned, so a
            // network that cannot reach the location services still protects.
            let consensus = try await fetchIPv4Consensus(proxy: proxy)
            verification = ConnectionVerificationResult(
                ip: consensus.ip,
                country: displayCountry(
                    for: consensus,
                    knownIPv4: knownIPv4,
                    knownCountry: knownCountry
                )
            )

        case .sameCountry:
            verification = try await fetchSameCountryConsensus(
                proxy: proxy,
                allowedCountries: allowedCountries,
                    knownIPv4: knownIPv4,
                knownCountry: knownCountry
            )
        }

        let ipv6: IPv6Inspection
        if toleratesIPv6Failure {
            ipv6 = (try? await ipv6Task) ?? IPv6Inspection(
                publicIPv6: nil,
                directIPv6: nil,
                leakStatus: .unverified
            )
        } else {
            ipv6 = try await ipv6Task
        }

        let finalProxy = currentProxyState()
        let finalRoute = NetworkRouteReader.current(proxy: finalProxy)
        guard routeRemainedStable(
            initialProxy: proxy,
            initialRoute: route,
            finalProxy: finalProxy,
            finalRoute: finalRoute
        ) else {
            throw IPServiceError.routeChangedDuringVerification
        }

        return observation(
            ipv4: verification.ip,
            country: verification.country,
            ipv6: ipv6,
            route: route
        )
    }

    static func routeRemainedStable(
        initialProxy: SystemProxyState,
        initialRoute: NetworkRouteIdentity,
        finalProxy: SystemProxyState,
        finalRoute: NetworkRouteIdentity
    ) -> Bool {
        initialProxy == finalProxy && initialRoute.signature == finalRoute.signature
    }

    private static func fetchIPv4Consensus(
        proxy: SystemProxyState
    ) async throws -> IPv4ConsensusResult {
        let primaryAttempts = await runPrimaryProviders(proxy: proxy, policy: .exactIP, allowedCountries: [])
        if let result = consensusResult(from: primaryAttempts) {
            return result
        }

        let secondaryAttempts = await runSecondaryProviders(
            proxy: proxy,
            policy: .exactIP,
            allowedCountries: []
        )
        let allAttempts = primaryAttempts + secondaryAttempts
        if let result = consensusResult(from: allAttempts) {
            return result
        }

        throw consensusError(for: allAttempts)
    }

    /// The address the trusted baseline was built on, when consensus still
    /// reports it. Returning the country that was verified for that address is
    /// the same inference the Exact IP display path makes for an unchanged address.
    private static func unchangedAddressResult(
        from attempts: [ProviderAttempt],
        knownIPv4: String?,
        knownCountry: String?
    ) -> ConnectionVerificationResult? {
        guard TrustedAddressFallback.acceptsUnchangedAddress(
            consensusIPv4: consensusResult(from: attempts)?.ip,
            knownIPv4: knownIPv4
        ), let knownIPv4 else {
            return nil
        }
        return ConnectionVerificationResult(
            ip: knownIPv4,
            country: normalizedCountry(knownCountry)
        )
    }

    private static func fetchSameCountryConsensus(
        proxy: SystemProxyState,
        allowedCountries: [String],
        knownIPv4: String?,
        knownCountry: String?
    ) async throws -> ConnectionVerificationResult {
        let primaryAttempts = await runPrimaryProviders(proxy: proxy, policy: .sameCountry, allowedCountries: allowedCountries)
        if let disagreement = countryDisagreement(in: primaryAttempts) {
            if let unchanged = unchangedAddressResult(
                from: primaryAttempts,
                knownIPv4: knownIPv4,
                knownCountry: knownCountry
            ) {
                return unchanged
            }
            throw IPServiceError.countryDisagreement(
                disagreement,
                providerDetails(primaryAttempts)
            )
        }
        if let result = directCountryConsensusResult(from: primaryAttempts, allowedCountries: allowedCountries) {
            return result
        }

        let secondaryAttempts = await runSecondaryProviders(
            proxy: proxy,
            policy: .sameCountry,
            allowedCountries: allowedCountries
        )
        let allAttempts = primaryAttempts + secondaryAttempts
        let unchangedAddress = unchangedAddressResult(
            from: allAttempts,
            knownIPv4: knownIPv4,
            knownCountry: knownCountry
        )
        if let disagreement = countryDisagreement(in: allAttempts) {
            if let unchangedAddress { return unchangedAddress }
            throw IPServiceError.countryDisagreement(
                disagreement,
                providerDetails(allAttempts)
            )
        }
        if let result = directCountryConsensusResult(from: allAttempts, allowedCountries: allowedCountries) {
            return result
        }

        let successful = allAttempts.compactMap(\.value)
        let providerContext = providerDetails(allAttempts)
        guard let representative = representativeProvider(from: successful) else {
            throw IPServiceError.noProviderResponded(providerContext)
        }

        let directVotes = countryVotes(from: allAttempts)
        do {
            let verified = try await verifiedCountry(
                for: representative.ip,
                providerVotes: directVotes,
                proxy: proxy,
                timeout: countryTimeout,
                allowedCountries: allowedCountries
            )
            return ConnectionVerificationResult(
                ip: representative.ip,
                country: verified
            )
        } catch IPServiceError.insufficientCountryConsensus(let details) {
            if let unchangedAddress { return unchangedAddress }
            throw IPServiceError.insufficientCountryConsensus(
                "\(providerContext) · \(details)"
            )
        } catch IPServiceError.countryDisagreement(let values, let details) {
            if let unchangedAddress { return unchangedAddress }
            throw IPServiceError.countryDisagreement(
                values,
                "\(providerContext) · \(details)"
            )
        } catch {
            throw error
        }
    }

    private static func runPrimaryProviders(
        proxy: SystemProxyState,
        policy: IPChangePolicy,
        allowedCountries: [String]
    ) async -> [ProviderAttempt] {
        await withTaskGroup(
            of: ProviderAttempt.self,
            returning: [ProviderAttempt].self
        ) { group in
            group.addTask {
                await attempt(provider: "Cloudflare Trace") {
                    try await fetchCloudflareTrace(
                        proxy: proxy,
                        timeout: primaryProviderTimeout
                    )
                }
            }
            group.addTask {
                await attempt(provider: "Country.is") {
                    try await fetchCountryIs(
                        proxy: proxy,
                        timeout: primaryProviderTimeout
                    )
                }
            }
            group.addTask {
                await attempt(provider: "AWS Check IP") {
                    try await fetchAWSCheckIP(
                        proxy: proxy,
                        timeout: primaryProviderTimeout
                    )
                }
            }

            var attempts: [ProviderAttempt] = []
            for await attempt in group {
                attempts.append(attempt)
                // Same Country must observe every launched country-capable
                // primary result so a late disagreement is never hidden by
                // an earlier pair of matching responses.
                if policy == .exactIP,
                   providerConsensusAvailable(
                       in: attempts,
                       policy: policy,
                       allowedCountries: allowedCountries
                   ) {
                    group.cancelAll()
                    return attempts
                }
            }
            return attempts
        }
    }

    private static func runSecondaryProviders(
        proxy: SystemProxyState,
        policy: IPChangePolicy,
        allowedCountries: [String]
    ) async -> [ProviderAttempt] {
        await withTaskGroup(
            of: ProviderAttempt.self,
            returning: [ProviderAttempt].self
        ) { group in
            group.addTask {
                await attempt(provider: "Cloudflare Meta") {
                    try await fetchCloudflareMeta(
                        proxy: proxy,
                        timeout: secondaryProviderTimeout
                    )
                }
            }
            group.addTask {
                await attempt(provider: "ident.me") {
                    try await fetchIdentMe(
                        proxy: proxy,
                        timeout: secondaryProviderTimeout
                    )
                }
            }
            group.addTask {
                await attempt(provider: "ipify") {
                    try await fetchIPify(
                        proxy: proxy,
                        timeout: secondaryProviderTimeout
                    )
                }
            }
            group.addTask {
                await attempt(provider: "icanhazip") {
                    try await fetchICanHazIP(
                        proxy: proxy,
                        timeout: secondaryProviderTimeout
                    )
                }
            }
            group.addTask {
                await attempt(provider: "ifconfig.me") {
                    try await fetchIfConfigMe(
                        proxy: proxy,
                        timeout: secondaryProviderTimeout
                    )
                }
            }

            var attempts: [ProviderAttempt] = []
            for await attempt in group {
                attempts.append(attempt)
                if providerConsensusAvailable(
                    in: attempts,
                    policy: policy,
                    allowedCountries: allowedCountries
                ) {
                    group.cancelAll()
                    return attempts
                }
            }
            return attempts
        }
    }

    private static func providerConsensusAvailable(
        in attempts: [ProviderAttempt],
        policy: IPChangePolicy,
        allowedCountries: [String]
    ) -> Bool {
        switch policy {
        case .exactIP:
            // Agreement on the address is the whole question, so the moment it
            // is settled there is nothing left to wait for.
            return consensusResult(from: attempts) != nil
        case .sameCountry:
            return directCountryConsensusResult(
                from: attempts,
                allowedCountries: allowedCountries
            ) != nil
        }
    }

    private static func directCountryConsensusResult(
        from attempts: [ProviderAttempt],
        allowedCountries: [String]
    ) -> ConnectionVerificationResult? {
        let successful = attempts.compactMap(\.value)
        guard case .confirmed(let country) = CountryVerdict.evaluate(
            votes: successful.compactMap(\.country),
            allowedCountries: allowedCountries,
            minimumAgreement: minimumCountryAgreement
        ), let representative = representativeProvider(
            from: successful,
            matchingCountry: country
        ) else {
            return nil
        }

        return ConnectionVerificationResult(ip: representative.ip, country: country)
    }

    private static func representativeProvider(
        from results: [ProviderIPv4],
        matchingCountry: String? = nil
    ) -> ProviderIPv4? {
        let matching = results.filter { result in
            guard let matchingCountry else { return true }
            return normalizedCountry(result.country) == matchingCountry
        }
        let priority = [
            "Cloudflare Trace",
            "Country.is",
            "AWS Check IP",
            "Cloudflare Meta",
            "ident.me",
            "ipify",
            "icanhazip",
            "ifconfig.me"
        ]
        return matching.min { lhs, rhs in
            let left = priority.firstIndex(of: lhs.provider) ?? priority.count
            let right = priority.firstIndex(of: rhs.provider) ?? priority.count
            if left != right { return left < right }
            return lhs.provider < rhs.provider
        }
    }

    private static func countryVotes(
        from attempts: [ProviderAttempt]
    ) -> [CountryVote] {
        attempts.compactMap { attempt in
            if let country = normalizedCountry(attempt.value?.country) {
                return CountryVote(
                    provider: attempt.provider,
                    country: country,
                    errorMessage: nil
                )
            }
            guard attempt.provider == "Cloudflare Trace"
                    || attempt.provider == "Country.is"
                    || attempt.provider == "Cloudflare Meta" else {
                return nil
            }
            return CountryVote(
                provider: attempt.provider,
                country: nil,
                errorMessage: attempt.errorMessage ?? "country unavailable"
            )
        }
    }

    private static func countryDisagreement(
        in attempts: [ProviderAttempt]
    ) -> [String]? {
        let countries = Array(
            Set(countryVotes(from: attempts).compactMap(\.country))
        ).sorted()
        return countries.count > 1 ? countries : nil
    }

    private static func consensusResult(
        from attempts: [ProviderAttempt]
    ) -> IPv4ConsensusResult? {
        let results = attempts.compactMap(\.value)
        guard let ipv4 = IPConsensus.selectIP(
            from: results.map(\.ip),
            minimumAgreement: minimumIPv4Agreement
        ) else {
            return nil
        }
        let agreeing = results.filter { $0.ip == ipv4 }
        return IPv4ConsensusResult(
            ip: ipv4,
            agreeingResults: agreeing
        )
    }

    private static func consensusError(
        for attempts: [ProviderAttempt]
    ) -> IPServiceError {
        let successful = attempts.compactMap(\.value)
        let details = providerDetails(attempts)
        guard !successful.isEmpty else {
            return .noProviderResponded(details)
        }

        let uniqueIPs = Array(Set(successful.map(\.ip))).sorted()
        if successful.count >= minimumIPv4Agreement, uniqueIPs.count > 1 {
            return .providerDisagreement(uniqueIPs, details)
        }
        return .insufficientProviderConsensus(
            successful: successful.count,
            total: attempts.count,
            details: details
        )
    }

    private static func providerDetails(_ attempts: [ProviderAttempt]) -> String {
        attempts
            .sorted { $0.provider.localizedCaseInsensitiveCompare($1.provider) == .orderedAscending }
            .map(\.summary)
            .joined(separator: " · ")
    }

    private static func attempt(
        provider: String,
        _ operation: @escaping @Sendable () async throws -> ProviderIPv4
    ) async -> ProviderAttempt {
        do {
            return ProviderAttempt(
                provider: provider,
                value: try await operation(),
                timedOut: false,
                errorMessage: nil
            )
        } catch IPServiceError.timedOut {
            return ProviderAttempt(
                provider: provider,
                value: nil,
                timedOut: true,
                errorMessage: "timed out"
            )
        } catch {
            return ProviderAttempt(
                provider: provider,
                value: nil,
                timedOut: false,
                errorMessage: compactError(error)
            )
        }
    }

    private static func compactError(_ error: Error) -> String {
        let raw: String
        if let localized = error as? LocalizedError,
           let description = localized.errorDescription {
            raw = description
        } else {
            raw = error.localizedDescription
        }
        let compact = raw
            .replacingOccurrences(of: "\\s+", with: " ", options: .regularExpression)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return String(compact.prefix(120))
    }

    private static func fetchCloudflareTrace(
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        let url = URL(string: "https://www.cloudflare.com/cdn-cgi/trace")!
        let data = try await routeData(url: url, proxy: proxy, timeout: timeout)
        guard let text = String(data: data, encoding: .utf8) else {
            throw IPServiceError.invalidResponse("Cloudflare Trace")
        }

        var values: [String: String] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let pair = line.split(separator: "=", maxSplits: 1).map(String.init)
            if pair.count == 2 { values[pair[0]] = pair[1] }
        }

        guard let ip = values["ip"], isIPv4(ip) else {
            throw IPServiceError.invalidResponse("Cloudflare Trace")
        }
        return ProviderIPv4(
            ip: ip,
            provider: "Cloudflare Trace",
            country: normalizedCountry(values["loc"])
        )
    }

    private static func fetchCountryIs(
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        let url = URL(string: "https://api.country.is/")!
        let data = try await routeData(url: url, proxy: proxy, timeout: timeout)
        let decoded = try JSONDecoder().decode(CountryIsResponse.self, from: data)
        guard isIPv4(decoded.ip),
              let country = normalizedCountry(decoded.country) else {
            throw IPServiceError.invalidResponse("Country.is")
        }
        return ProviderIPv4(
            ip: decoded.ip,
            provider: "Country.is",
            country: country
        )
    }

    private static func fetchCloudflareMeta(
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        let url = URL(string: "https://speed.cloudflare.com/meta")!
        let data = try await routeData(url: url, proxy: proxy, timeout: timeout)
        let decoded = try JSONDecoder().decode(CloudflareMetaResponse.self, from: data)
        guard isIPv4(decoded.clientIp),
              let country = normalizedCountry(decoded.country) else {
            throw IPServiceError.invalidResponse("Cloudflare Meta")
        }
        return ProviderIPv4(
            ip: decoded.clientIp,
            provider: "Cloudflare Meta",
            country: country
        )
    }

    private static func fetchAWSCheckIP(
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        try await fetchPlainTextIPv4(
            provider: "AWS Check IP",
            url: URL(string: "https://checkip.amazonaws.com/")!,
            proxy: proxy,
            timeout: timeout
        )
    }

    private static func fetchIdentMe(
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        try await fetchPlainTextIPv4(
            provider: "ident.me",
            url: URL(string: "https://4.ident.me/")!,
            proxy: proxy,
            timeout: timeout
        )
    }

    private static func fetchIPify(
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        let url = URL(string: "https://api.ipify.org?format=json")!
        let data = try await routeData(url: url, proxy: proxy, timeout: timeout)
        let decoded = try JSONDecoder().decode(IPifyResponse.self, from: data)
        guard isIPv4(decoded.ip) else { throw IPServiceError.invalidResponse("ipify") }
        return ProviderIPv4(ip: decoded.ip, provider: "ipify", country: nil)
    }

    private static func fetchICanHazIP(
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        try await fetchPlainTextIPv4(
            provider: "icanhazip",
            url: URL(string: "https://ipv4.icanhazip.com/")!,
            proxy: proxy,
            timeout: timeout
        )
    }

    private static func fetchIfConfigMe(
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        try await fetchPlainTextIPv4(
            provider: "ifconfig.me",
            url: URL(string: "https://ipv4.ifconfig.me/ip")!,
            proxy: proxy,
            timeout: timeout
        )
    }

    private static func fetchPlainTextIPv4(
        provider: String,
        url: URL,
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> ProviderIPv4 {
        let data = try await routeData(url: url, proxy: proxy, timeout: timeout)
        guard let value = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines),
              isIPv4(value) else {
            throw IPServiceError.invalidResponse(provider)
        }
        return ProviderIPv4(ip: value, provider: provider, country: nil)
    }

    /// A country to show beside the address under Exact IP. Free information
    /// only: the country the trusted address already carried, or one the
    /// address providers reported in the same response. Nothing is requested
    /// for it and nothing fails without it.
    private static func displayCountry(
        for consensus: IPv4ConsensusResult,
        knownIPv4: String?,
        knownCountry: String?
    ) -> String? {
        if consensus.ip == knownIPv4, let known = normalizedCountry(knownCountry) {
            return known
        }
        return CountryConsensus.selectCountry(
            from: consensus.agreeingResults.compactMap { normalizedCountry($0.country) },
            minimumAgreement: 1
        )
    }

    private static func verifiedCountry(
        for ipv4: String,
        providerVotes: [CountryVote],
        proxy: SystemProxyState,
        timeout: TimeInterval,
        allowedCountries: [String]
    ) async throws -> String {
        // A settled answer ends it immediately. Anything short of that goes on
        // to ask the fallback services before giving an answer.
        if case .confirmed(let country) = CountryVerdict.evaluate(
            votes: providerVotes.compactMap(\.country),
            allowedCountries: allowedCountries,
            minimumAgreement: minimumCountryAgreement
        ) {
            return country
        }

        let fallbackVotes = await withTaskGroup(
            of: CountryVote.self,
            returning: [CountryVote].self
        ) { group in
            group.addTask {
                await countryAttempt(provider: "ipwho.is") {
                    try await fetchIPWhoCountry(
                        for: ipv4,
                        proxy: proxy,
                        timeout: timeout
                    )
                }
            }
            group.addTask {
                await countryAttempt(provider: "ipapi.co") {
                    try await fetchIPAPICountry(
                        for: ipv4,
                        proxy: proxy,
                        timeout: timeout
                    )
                }
            }

            var votes: [CountryVote] = []
            for await vote in group {
                votes.append(vote)
            }
            return votes
        }

        let allVotes = providerVotes + fallbackVotes
        let details = allVotes.map(\.summary).joined(separator: " · ")
        switch CountryVerdict.evaluate(
            votes: allVotes.compactMap(\.country),
            allowedCountries: allowedCountries,
            minimumAgreement: minimumCountryAgreement
        ) {
        case .confirmed(let country):
            return country
        case .conflicting(let countries):
            throw IPServiceError.countryDisagreement(countries, details)
        case .insufficient:
            throw IPServiceError.insufficientCountryConsensus(details)
        }
    }

    private static func countryAttempt(
        provider: String,
        _ operation: @escaping @Sendable () async throws -> String
    ) async -> CountryVote {
        if await countryProviderCooldown.isResting(provider) {
            return CountryVote(
                provider: provider,
                country: nil,
                errorMessage: "resting after rate limit"
            )
        }
        do {
            let country = normalizedCountry(try await operation())
            await countryProviderCooldown.recordSuccess(provider)
            return CountryVote(
                provider: provider,
                country: country,
                errorMessage: nil
            )
        } catch IPServiceError.rateLimited(let limited) {
            let until = await countryProviderCooldown.recordRateLimit(limited)
            return CountryVote(
                provider: provider,
                country: nil,
                errorMessage: "rate limited until \(until)"
            )
        } catch {
            return CountryVote(
                provider: provider,
                country: nil,
                errorMessage: compactError(error)
            )
        }
    }

    private static func fetchIPWhoCountry(
        for ipv4: String,
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> String {
        let encoded = ipv4.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ipv4
        let url = URL(string: "https://ipwho.is/\(encoded)")!
        let data = try await routeData(url: url, proxy: proxy, timeout: timeout)
        let decoded = try JSONDecoder().decode(IPWhoResponse.self, from: data)
        guard decoded.success != false,
              let country = normalizedCountry(decoded.country_code) else {
            throw IPServiceError.invalidResponse("ipwho.is")
        }
        return country
    }

    private static func fetchIPAPICountry(
        for ipv4: String,
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> String {
        let encoded = ipv4.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ipv4
        let url = URL(string: "https://ipapi.co/\(encoded)/country/")!
        let data = try await routeData(url: url, proxy: proxy, timeout: timeout)
        guard let country = String(data: data, encoding: .utf8)
            .map({ $0.trimmingCharacters(in: .whitespacesAndNewlines) }),
              let normalized = normalizedCountry(country) else {
            throw IPServiceError.invalidResponse("ipapi.co")
        }
        return normalized
    }

    private static func observation(
        ipv4: String,
        country: String?,
        ipv6: IPv6Inspection,
        route: NetworkRouteIdentity
    ) -> IPObservation {
        IPObservation(
            ipv4: ipv4,
            ipv6: ipv6.publicIPv6,
            directIPv6: ipv6.directIPv6,
            ipv6LeakStatus: ipv6.leakStatus,
            countryLabel: country,
            checkedAt: Date(),
            routeSignature: route.signature,
            proxySummary: route.userFacingSummary
        )
    }

    private static func inspectIPv6(
        proxy: SystemProxyState,
        route: NetworkRouteIdentity
    ) async throws -> IPv6Inspection {
        let physicalInterface = route.physicalInterface
        let hasPhysicalIPv6 = hasGlobalIPv6Interface(named: physicalInterface)

        if proxy.hasAnyProxy {
            guard hasPhysicalIPv6 else {
                return IPv6Inspection(
                    publicIPv6: nil,
                    directIPv6: nil,
                    leakStatus: .noLeakDetected
                )
            }

            let direct = await probeIPv6(boundTo: physicalInterface)
            if let leaked = direct.resolvedAddress {
                return IPv6Inspection(
                    publicIPv6: nil,
                    directIPv6: leaked,
                    leakStatus: .leakDetected
                )
            }
            // A configured address that cannot carry traffic is not a leak.
            guard direct.provesNoIPv6Path else {
                throw IPServiceError.ipv6VerificationFailed
            }
            return IPv6Inspection(
                publicIPv6: nil,
                directIPv6: nil,
                leakStatus: .noLeakDetected
            )
        }

        if !route.tunnelInterfaces.isEmpty {
            let publicIPv6 = await probeIPv6(boundTo: nil).resolvedAddress
            guard hasPhysicalIPv6 else {
                return IPv6Inspection(
                    publicIPv6: publicIPv6,
                    directIPv6: nil,
                    leakStatus: .noLeakDetected
                )
            }
            let direct = await probeIPv6(boundTo: physicalInterface)
            if let leaked = direct.resolvedAddress {
                return IPv6Inspection(
                    publicIPv6: publicIPv6,
                    directIPv6: leaked,
                    leakStatus: .leakDetected
                )
            }
            guard direct.provesNoIPv6Path || publicIPv6 != nil else {
                throw IPServiceError.ipv6VerificationFailed
            }
            return IPv6Inspection(
                publicIPv6: publicIPv6,
                directIPv6: nil,
                leakStatus: .noLeakDetected
            )
        }

        guard hasGlobalIPv6Interface(named: nil) else {
            return IPv6Inspection(
                publicIPv6: nil,
                directIPv6: nil,
                leakStatus: .notApplicable
            )
        }

        let probe = await probeIPv6(boundTo: nil)
        if let publicIPv6 = probe.resolvedAddress {
            return IPv6Inspection(
                publicIPv6: publicIPv6,
                directIPv6: publicIPv6,
                leakStatus: .notApplicable
            )
        }
        // An address is configured but nothing can be reached through it, so
        // there is no public IPv6 to compare against later.
        guard probe.provesNoIPv6Path else {
            throw IPServiceError.ipv6VerificationFailed
        }
        return IPv6Inspection(
            publicIPv6: nil,
            directIPv6: nil,
            leakStatus: .notApplicable
        )
    }

    /// curl exit 7 is "failed to connect" and 45 is "interface error". Both mean
    /// the request never left this machine, which is exactly what "no IPv6 path"
    /// means. A timeout (28) or a name-resolution failure (6) proves nothing.
    private static let noIPv6PathExitCodes: Set<Int32> = [7, 45]

    private enum IPv6Probe: Sendable {
        case address(String)
        /// Every provider refused the connection outright, so no IPv6 traffic
        /// can leave through this interface at all.
        case unreachable
        /// Timed out or failed for a reason that settles nothing either way.
        case inconclusive

        var resolvedAddress: String? {
            if case .address(let value) = self { return value }
            return nil
        }

        var provesNoIPv6Path: Bool {
            if case .unreachable = self { return true }
            return false
        }
    }

    private static func probeIPv6(boundTo interface: String?) async -> IPv6Probe {
        let urls = [
            URL(string: "https://api6.ipify.org")!,
            URL(string: "https://ipv6.icanhazip.com/")!
        ]

        return await withTaskGroup(
            of: IPv6Probe.self,
            returning: IPv6Probe.self
        ) { group in
            for url in urls {
                group.addTask {
                    do {
                        let value = try await curlIPv6(url: url, interface: interface)
                        return isIPv6(value) ? .address(value.lowercased()) : .inconclusive
                    } catch IPServiceError.probeFailed(let status, _)
                        where noIPv6PathExitCodes.contains(status) {
                        return .unreachable
                    } catch {
                        return .inconclusive
                    }
                }
            }

            var sawInconclusive = false
            for await result in group {
                switch result {
                case .address:
                    group.cancelAll()
                    return result
                case .inconclusive:
                    sawInconclusive = true
                case .unreachable:
                    break
                }
            }
            // Only a clean refusal from every provider proves there is no path.
            return sawInconclusive ? .inconclusive : .unreachable
        }
    }

    private static func routeData(
        url: URL,
        proxy: SystemProxyState,
        timeout: TimeInterval
    ) async throws -> Data {
        var request = URLRequest(url: url)
        request.timeoutInterval = timeout
        request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        request.setValue("IPGuardian/1", forHTTPHeaderField: "User-Agent")
        request.setValue("no-cache, no-store", forHTTPHeaderField: "Cache-Control")

        let configuration = URLSessionConfiguration.ephemeral
        configuration.urlCache = nil
        configuration.httpCookieStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.timeoutIntervalForRequest = timeout
        configuration.timeoutIntervalForResource = timeout + 0.8
        configuration.waitsForConnectivity = false
        configuration.connectionProxyDictionary = proxy.connectionProxyDictionary

        let session = URLSession(configuration: configuration)
        defer { session.invalidateAndCancel() }

        do {
            let (data, response) = try await session.data(for: request)
            try validate(response, provider: url.host ?? "provider")
            return data
        } catch let error as URLError {
            switch error.code {
            case .timedOut:
                throw IPServiceError.timedOut
            case .notConnectedToInternet, .networkConnectionLost, .cannotFindHost:
                throw IPServiceError.networkUnavailable
            default:
                throw error
            }
        }
    }

    private static func curlIPv6(url: URL, interface: String?) async throws -> String {
        let data = try await curlData(
            url: url,
            timeout: ipv6Timeout,
            interface: interface
        )
        guard let value = String(data: data, encoding: .utf8)?
            .trimmingCharacters(in: .whitespacesAndNewlines) else {
            throw IPServiceError.invalidResponse("IPv6 provider")
        }
        return value
    }

    private static func curlData(
        url: URL,
        timeout: TimeInterval,
        interface: String?
    ) async throws -> Data {
        let urlString = url.absoluteString
        let processBox = CurlProcessBox()
        return try await withTaskCancellationHandler(operation: {
            try await Task.detached(priority: .utility) {
                let process = Process()
                let temporaryDirectory = FileManager.default.temporaryDirectory
                let outputURL = temporaryDirectory.appendingPathComponent(UUID().uuidString)
                let errorURL = temporaryDirectory.appendingPathComponent(UUID().uuidString)

                guard FileManager.default.createFile(atPath: outputURL.path, contents: nil),
                      FileManager.default.createFile(atPath: errorURL.path, contents: nil) else {
                    throw IPServiceError.proxyCommandFailed("Temporary output files could not be created.")
                }
                defer {
                    try? FileManager.default.removeItem(at: outputURL)
                    try? FileManager.default.removeItem(at: errorURL)
                }

                let output = try FileHandle(forWritingTo: outputURL)
                let errors = try FileHandle(forWritingTo: errorURL)
                defer {
                    try? output.close()
                    try? errors.close()
                }

                guard processBox.attach(process) else {
                    throw CancellationError()
                }
                defer { processBox.detach(process) }

                var arguments = [
                    "-sS",
                    "--fail",
                    "--location",
                    "--http1.1",
                    "--connect-timeout", "2",
                    "--max-time", String(timeout),
                    "--header", "Cache-Control: no-cache",
                    "--user-agent", "IPGuardian/1"
                ]
                arguments.append("-6")
                arguments.append(contentsOf: ["--noproxy", "*"])
                if let interface, !interface.isEmpty {
                    arguments.append(contentsOf: ["--interface", interface])
                }
                arguments.append(urlString)

                process.executableURL = URL(fileURLWithPath: "/usr/bin/curl")
                process.arguments = arguments
                process.standardOutput = output
                process.standardError = errors

                do {
                    try process.run()
                    process.waitUntilExit()
                } catch {
                    throw IPServiceError.proxyCommandFailed(error.localizedDescription)
                }

                try? output.synchronize()
                try? errors.synchronize()
                let data = try Data(contentsOf: outputURL)
                let errorData = try Data(contentsOf: errorURL)
                guard process.terminationStatus == 0 else {
                    if process.terminationStatus == 28 { throw IPServiceError.timedOut }
                    let detail = String(data: errorData, encoding: .utf8)?
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    throw IPServiceError.probeFailed(
                        status: process.terminationStatus,
                        detail: detail?.isEmpty == false
                            ? detail!
                            : "curl exit \(process.terminationStatus)"
                    )
                }
                return data
            }.value
        }, onCancel: {
            processBox.cancel()
        })
    }

    private static func validate(_ response: URLResponse, provider: String) throws {
        guard let response = response as? HTTPURLResponse else {
            throw IPServiceError.invalidResponse(provider)
        }
        if response.statusCode == 429 {
            throw IPServiceError.rateLimited(provider)
        }
        guard (200..<300).contains(response.statusCode) else {
            throw IPServiceError.invalidResponse(provider)
        }
    }

    private static func normalizedCountry(_ value: String?) -> String? {
        CountryCode.resolved(value)
    }

    private static func isIPv4(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_pton(AF_INET, $0, &address) == 1 }
    }

    private static func isIPv6(_ value: String) -> Bool {
        var address = in6_addr()
        return value.withCString { inet_pton(AF_INET6, $0, &address) == 1 }
    }

    private static func hasGlobalIPv6Interface(named interface: String?) -> Bool {
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return false }
        defer { freeifaddrs(pointer) }

        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let item = cursor {
            let entry = item.pointee
            cursor = entry.ifa_next

            guard let address = entry.ifa_addr,
                  Int32(address.pointee.sa_family) == AF_INET6,
                  Int32(entry.ifa_flags) & IFF_UP != 0,
                  Int32(entry.ifa_flags) & IFF_RUNNING != 0,
                  let namePointer = entry.ifa_name else { continue }

            let name = String(cString: namePointer)
            if let interface, name != interface { continue }

            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            let result = getnameinfo(
                address,
                socklen_t(address.pointee.sa_len),
                &host,
                socklen_t(host.count),
                nil,
                0,
                NI_NUMERICHOST
            )
            guard result == 0 else { continue }
            let value = String(cString: host).lowercased()
            if value != "::1",
               !value.hasPrefix("fe80:"),
               !value.hasPrefix("fc"),
               !value.hasPrefix("fd") {
                return true
            }
        }
        return false
    }
}
