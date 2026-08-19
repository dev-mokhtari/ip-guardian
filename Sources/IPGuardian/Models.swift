import Darwin
import Foundation

/// The network half of an IPv6 address.
///
/// macOS hands out temporary addresses (RFC 4941) and rotates the interface
/// half of them on a perfectly healthy connection. Only the /64 network prefix
/// identifies the path traffic actually takes, so comparing whole addresses
/// reports a routine rotation as a connection change.
enum IPv6Prefix {
    static func network(_ value: String?) -> String? {
        guard let value else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        // A zone index ("fe80::1%en0") identifies the interface, not the address.
        let bare = trimmed.split(separator: "%", maxSplits: 1).first.map(String.init)
        guard let bare, !bare.isEmpty else { return nil }

        var address = in6_addr()
        guard bare.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else {
            return nil
        }
        let bytes = withUnsafeBytes(of: &address) { Array($0.prefix(8)) }
        return stride(from: 0, to: bytes.count, by: 2)
            .map { String(format: "%02x%02x", bytes[$0], bytes[$0 + 1]) }
            .joined(separator: ":")
    }
}

enum CountryCode {
    static func normalized(_ countryCode: String?) -> String? {
        guard let countryCode else { return nil }
        let code = countryCode
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .uppercased()
        let scalars = Array(code.unicodeScalars)
        guard scalars.count == 2,
              scalars.allSatisfy({ (65...90).contains(Int($0.value)) }) else {
            return nil
        }
        return code
    }

    /// Providers answer "XX" when they cannot place an address. It has the
    /// shape of a country code but names no country, so it must never be read
    /// as a country the user did not allow.
    static let unknownPlaceholder = "XX"

    static func resolved(_ countryCode: String?) -> String? {
        guard let code = normalized(countryCode), code != unknownPlaceholder else {
            return nil
        }
        return code
    }
}

struct ProtectedApp: Codable, Identifiable, Hashable, Sendable {
    let id: UUID
    var name: String
    var bundleIdentifier: String?
    var path: String

    init(
        id: UUID = UUID(),
        name: String,
        bundleIdentifier: String?,
        path: String
    ) {
        self.id = id
        self.name = name
        self.bundleIdentifier = bundleIdentifier
        self.path = path
    }
}

enum IPv6LeakStatus: String, Hashable, Sendable {
    case notApplicable
    case noLeakDetected
    case leakDetected
    case unverified

    var displayName: String {
        switch self {
        case .notApplicable: return "Not applicable"
        case .noLeakDetected: return "No leak detected"
        case .leakDetected: return "Direct IPv6 leak detected"
        case .unverified: return "Unknown"
        }
    }
}

struct IPObservation: Equatable, Sendable {
    let ipv4: String
    let ipv6: String?
    let directIPv6: String?
    let ipv6LeakStatus: IPv6LeakStatus
    let countryLabel: String?
    let checkedAt: Date
    let routeSignature: String?
    let proxySummary: String?

    init(
        ipv4: String,
        ipv6: String?,
        directIPv6: String? = nil,
        ipv6LeakStatus: IPv6LeakStatus = .notApplicable,
        countryLabel: String?,
        checkedAt: Date,
        routeSignature: String? = nil,
        proxySummary: String? = nil
    ) {
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        self.directIPv6 = directIPv6
        self.ipv6LeakStatus = ipv6LeakStatus
        self.countryLabel = countryLabel
        self.checkedAt = checkedAt
        self.routeSignature = routeSignature
        self.proxySummary = proxySummary
    }
}

struct EventRecord: Identifiable {
    let id: UUID
    let date: Date
    let level: String
    let message: String
    let occurrenceCount: Int

    init(
        id: UUID = UUID(),
        date: Date = Date(),
        level: String,
        message: String,
        occurrenceCount: Int = 1
    ) {
        self.id = id
        self.date = date
        self.level = level
        self.message = message
        self.occurrenceCount = max(1, occurrenceCount)
    }
}

/// Applies the user-visible Recent Activity rules independently from the
/// controller so retry and recovery transitions cannot accidentally rewrite
/// earlier records.
enum ActivityRecordPolicy {
    static func adding(
        level: String,
        message: String,
        to records: [EventRecord],
        maximumRecords: Int,
        date: Date = Date()
    ) -> [EventRecord] {
        var updated = records
        let collapsibleLevels = ["WARN", "ERROR", "CRITICAL"]

        if collapsibleLevels.contains(level),
           let index = updated.firstIndex(where: {
               $0.level == level && $0.message == message
           }) {
            let existing = updated.remove(at: index)
            updated.insert(
                EventRecord(
                    id: existing.id,
                    date: date,
                    level: existing.level,
                    message: existing.message,
                    occurrenceCount: existing.occurrenceCount + 1
                ),
                at: 0
            )
        } else if level == "INFO",
                  let newest = updated.first,
                  newest.level == level,
                  newest.message == message {
            // Repeated green status messages add no useful information.
            return updated
        } else {
            updated.insert(
                EventRecord(date: date, level: level, message: message),
                at: 0
            )
        }

        let limit = max(1, maximumRecords)
        if updated.count > limit {
            updated.removeLast(updated.count - limit)
        }
        return updated
    }
}

enum GuardianMode: String {
    case off
    case checking
    case protected
    case unverified
    case unsafe

    var title: String {
        switch self {
        case .off: return "Protection Off"
        case .checking: return "Checking Connection"
        case .protected: return "Protected"
        case .unverified: return "Connection Unverified"
        case .unsafe: return "Unsafe Connection"
        }
    }

    var symbolName: String {
        switch self {
        case .off: return "shield.slash"
        case .checking: return "arrow.triangle.2.circlepath"
        case .protected: return "checkmark.shield.fill"
        case .unverified: return "exclamationmark.triangle.fill"
        case .unsafe: return "xmark.shield.fill"
        }
    }
}

enum IPChangePolicy: String, Identifiable, Sendable {
    case exactIP
    case sameCountry

    var id: String { rawValue }

    var title: String {
        switch self {
        case .exactIP: return "Exact IP"
        case .sameCountry: return "Same Country"
        }
    }
}

enum ProtectedAppsDisposition: String, Sendable {
    case notProtected
    case running
    case paused
    case closed

    var title: String {
        switch self {
        case .notProtected: return "Not protected"
        case .running: return "Running"
        case .paused: return "Paused"
        case .closed: return "Closed"
        }
    }
}
