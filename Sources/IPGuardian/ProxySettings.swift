import CFNetwork
import Darwin
import Foundation

struct SystemProxyState: Equatable, Sendable {
    let socksEnabled: Bool
    let socksHost: String?
    let socksPort: Int?
    let httpEnabled: Bool
    let httpHost: String?
    let httpPort: Int?
    let httpsEnabled: Bool
    let httpsHost: String?
    let httpsPort: Int?
    let pacEnabled: Bool
    let pacURL: String?
    let autoDiscoveryEnabled: Bool

    static let direct = SystemProxyState(
        socksEnabled: false,
        socksHost: nil,
        socksPort: nil,
        httpEnabled: false,
        httpHost: nil,
        httpPort: nil,
        httpsEnabled: false,
        httpsHost: nil,
        httpsPort: nil,
        pacEnabled: false,
        pacURL: nil,
        autoDiscoveryEnabled: false
    )

    var hasValidSOCKS: Bool { valid(enabled: socksEnabled, host: socksHost, port: socksPort) }
    var hasValidHTTP: Bool { valid(enabled: httpEnabled, host: httpHost, port: httpPort) }
    var hasValidHTTPS: Bool { valid(enabled: httpsEnabled, host: httpsHost, port: httpsPort) }
    var hasValidPAC: Bool { pacEnabled && !(pacURL?.isEmpty ?? true) }
    var hasValidAutoDiscovery: Bool { autoDiscoveryEnabled }
    var hasAnyProxy: Bool {
        hasValidSOCKS || hasValidHTTP || hasValidHTTPS || hasValidPAC || hasValidAutoDiscovery
    }
    var hasIncompleteConfiguration: Bool {
        (socksEnabled && !hasValidSOCKS)
            || (httpEnabled && !hasValidHTTP)
            || (httpsEnabled && !hasValidHTTPS)
            || (pacEnabled && !hasValidPAC)
    }

    var routeSignature: String {
        var parts: [String] = []
        if hasValidSOCKS, let socksHost, let socksPort {
            parts.append("socks5://\(socksHost.lowercased()):\(socksPort)")
        }
        if hasValidHTTPS, let httpsHost, let httpsPort {
            parts.append("https-proxy://\(httpsHost.lowercased()):\(httpsPort)")
        }
        if hasValidHTTP, let httpHost, let httpPort {
            parts.append("http-proxy://\(httpHost.lowercased()):\(httpPort)")
        }
        if hasValidPAC, let pacURL {
            parts.append("pac://\(pacURL)")
        }
        if hasValidAutoDiscovery { parts.append("wpad://enabled") }
        return parts.isEmpty ? "direct/system-default" : parts.joined(separator: "|")
    }

    var connectionProxyDictionary: [AnyHashable: Any]? {
        guard hasAnyProxy else { return nil }
        var values: [AnyHashable: Any] = [:]

        if hasValidSOCKS, let socksHost, let socksPort {
            values[kCFNetworkProxiesSOCKSEnable as String] = 1
            values[kCFNetworkProxiesSOCKSProxy as String] = socksHost
            values[kCFNetworkProxiesSOCKSPort as String] = socksPort
        }
        if hasValidHTTP, let httpHost, let httpPort {
            values[kCFNetworkProxiesHTTPEnable as String] = 1
            values[kCFNetworkProxiesHTTPProxy as String] = httpHost
            values[kCFNetworkProxiesHTTPPort as String] = httpPort
        }
        if hasValidHTTPS, let httpsHost, let httpsPort {
            values[kCFNetworkProxiesHTTPSEnable as String] = 1
            values[kCFNetworkProxiesHTTPSProxy as String] = httpsHost
            values[kCFNetworkProxiesHTTPSPort as String] = httpsPort
        }
        if hasValidPAC, let pacURL {
            values[kCFNetworkProxiesProxyAutoConfigEnable as String] = 1
            values[kCFNetworkProxiesProxyAutoConfigURLString as String] = pacURL
        }
        if hasValidAutoDiscovery {
            values[kCFNetworkProxiesProxyAutoDiscoveryEnable as String] = 1
        }
        return values
    }

    private func valid(enabled: Bool, host: String?, port: Int?) -> Bool {
        enabled
            && !(host?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ?? true)
            && (port ?? 0) > 0
            && (port ?? 0) <= 65_535
    }
}

struct NetworkRouteIdentity: Equatable, Sendable {
    let proxySignature: String
    let defaultInterface: String?
    let defaultIPv6Interface: String?
    let physicalInterface: String?
    let tunnelInterfaces: [String]
    let proxyConfigured: Bool
    let proxyConfigurationIncomplete: Bool

    init(
        proxySignature: String,
        defaultInterface: String?,
        defaultIPv6Interface: String?,
        physicalInterface: String? = nil,
        tunnelInterfaces: [String],
        proxyConfigured: Bool,
        proxyConfigurationIncomplete: Bool
    ) {
        self.proxySignature = proxySignature
        self.defaultInterface = defaultInterface
        self.defaultIPv6Interface = defaultIPv6Interface
        self.physicalInterface = physicalInterface
        self.tunnelInterfaces = tunnelInterfaces
        self.proxyConfigured = proxyConfigured
        self.proxyConfigurationIncomplete = proxyConfigurationIncomplete
    }

    static let direct = NetworkRouteIdentity(
        proxySignature: "direct/system-default",
        defaultInterface: nil,
        defaultIPv6Interface: nil,
        physicalInterface: nil,
        tunnelInterfaces: [],
        proxyConfigured: false,
        proxyConfigurationIncomplete: false
    )

    var signature: String {
        "proxy:\(proxySignature)|\(interfaceSignature)"
    }

    var interfaceSignature: String {
        let defaultValue = defaultInterface?.lowercased() ?? "unknown"
        let defaultIPv6Value = defaultIPv6Interface?.lowercased() ?? "unknown"
        let physicalValue = physicalInterface?.lowercased() ?? "unknown"
        let tunnels = tunnelInterfaces.map { $0.lowercased() }.sorted().joined(separator: ",")
        return "default4:\(defaultValue)|default6:\(defaultIPv6Value)|physical:\(physicalValue)|tunnels:\(tunnels.isEmpty ? "none" : tunnels)"
    }

    var userFacingSummary: String {
        if proxyConfigured { return "Proxy Connection" }
        if !tunnelInterfaces.isEmpty { return "VPN Tunnel" }
        return "Direct Connection"
    }

    var connectionPathSummary: String {
        "\(networkTransportSummary) → \(userFacingSummary)"
    }

    var networkTransportSummary: String {
        guard let physicalInterface else { return "Network" }
        return NetworkInterfaceDisplay.hardwarePortName(for: physicalInterface)
            ?? NetworkInterfaceDisplay.fallbackName(for: physicalInterface)
    }
}

enum NetworkRouteReader {
    static func current(proxy: SystemProxyState = SystemProxyReader.current()) -> NetworkRouteIdentity {
        let interfaces = activeInterfaceNames()
        let defaultInterface = defaultRouteInterface(ipv6: false)
        let defaultIPv6Interface = defaultRouteInterface(ipv6: true)
        let tunnelInterfaces = routeRelevantTunnelInterfaces(
            defaultIPv4: defaultInterface,
            defaultIPv6: defaultIPv6Interface
        )
        let physicalInterface = preferredPhysicalInterface(
            from: interfaces,
            defaultInterface: defaultInterface
        )
        return NetworkRouteIdentity(
            proxySignature: proxy.routeSignature,
            defaultInterface: defaultInterface,
            defaultIPv6Interface: defaultIPv6Interface,
            physicalInterface: physicalInterface,
            tunnelInterfaces: tunnelInterfaces,
            proxyConfigured: proxy.hasAnyProxy,
            proxyConfigurationIncomplete: proxy.hasIncompleteConfiguration
        )
    }

    static func routeRelevantTunnelInterfaces(
        defaultIPv4: String?,
        defaultIPv6: String?
    ) -> [String] {
        Array(Set([defaultIPv4, defaultIPv6].compactMap { $0 }))
            .filter(isTunnelInterface)
            .sorted()
    }

    private static func preferredPhysicalInterface(
        from interfaces: Set<String>,
        defaultInterface: String?
    ) -> String? {
        if let defaultInterface, !isTunnelInterface(defaultInterface) {
            return defaultInterface
        }
        if let routedPhysical = physicalDefaultRouteInterface(from: interfaces) {
            return routedPhysical
        }
        let physical = interfaces.filter { !isTunnelInterface($0) }.sorted()
        return physical.first { NetworkInterfaceDisplay.hardwarePortName(for: $0) != nil }
            ?? physical.first
    }

    private static func physicalDefaultRouteInterface(
        from interfaces: Set<String>
    ) -> String? {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/netstat")
        process.arguments = ["-rn", "-f", "inet"]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0,
                  let text = String(data: data, encoding: .utf8) else { return nil }
            return physicalInterface(
                fromRouteTable: text,
                activeInterfaces: interfaces
            )
        } catch {
            return nil
        }
    }

    static func physicalInterface(
        fromRouteTable text: String,
        activeInterfaces: Set<String>
    ) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            let fields = line.split(whereSeparator: \.isWhitespace).map(String.init)
            guard fields.first?.lowercased() == "default" else { continue }
            if let interface = fields.reversed().first(where: {
                activeInterfaces.contains($0) && !isTunnelInterface($0)
            }) {
                return interface
            }
        }
        return nil
    }

    private static func activeInterfaceNames() -> Set<String> {
        var pointer: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&pointer) == 0, let first = pointer else { return [] }
        defer { freeifaddrs(pointer) }

        var names = Set<String>()
        var cursor: UnsafeMutablePointer<ifaddrs>? = first
        while let item = cursor {
            let entry = item.pointee
            cursor = entry.ifa_next
            guard let address = entry.ifa_addr,
                  Int32(entry.ifa_flags) & IFF_UP != 0,
                  Int32(entry.ifa_flags) & IFF_RUNNING != 0,
                  let namePointer = entry.ifa_name else { continue }
            let family = Int32(address.pointee.sa_family)
            guard family == AF_INET || family == AF_INET6 else { continue }
            var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            guard getnameinfo(
                address,
                socklen_t(address.pointee.sa_len),
                &host,
                socklen_t(host.count),
                nil,
                0,
                NI_NUMERICHOST
            ) == 0 else { continue }
            let addressValue = String(cString: host).lowercased()
            if addressValue == "::1"
                || addressValue.hasPrefix("fe80:")
                || addressValue.hasPrefix("127.")
                || addressValue.hasPrefix("169.254.") {
                continue
            }
            let name = String(cString: namePointer)
            if name != "lo0" { names.insert(name) }
        }
        return names
    }

    private static func isTunnelInterface(_ name: String) -> Bool {
        let normalized = name.lowercased()
        return normalized.hasPrefix("utun")
            || normalized.hasPrefix("tun")
            || normalized.hasPrefix("tap")
            || normalized.hasPrefix("ppp")
            || normalized.hasPrefix("ipsec")
    }

    private static func defaultRouteInterface(ipv6: Bool) -> String? {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/sbin/route")
        process.arguments = ipv6
            ? ["-n", "get", "-inet6", "default"]
            : ["-n", "get", "default"]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0,
                  let text = String(data: data, encoding: .utf8) else { return nil }
            for line in text.split(whereSeparator: \.isNewline) {
                let value = String(line).trimmingCharacters(in: .whitespaces)
                guard value.hasPrefix("interface:") else { continue }
                let interface = value.dropFirst("interface:".count)
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                return interface.isEmpty ? nil : interface
            }
        } catch {
            return nil
        }
        return nil
    }
}

private enum NetworkInterfaceDisplay {
    private static let hardwarePorts: [String: String] = loadHardwarePorts()

    static func hardwarePortName(for device: String) -> String? {
        hardwarePorts[device]
    }

    private static func loadHardwarePorts() -> [String: String] {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/networksetup")
        process.arguments = ["-listallhardwareports"]
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile()
            process.waitUntilExit()
            guard process.terminationStatus == 0,
                  let text = String(data: data, encoding: .utf8) else { return [:] }

            var result: [String: String] = [:]
            var currentPort: String?
            for rawLine in text.split(whereSeparator: \.isNewline) {
                let line = String(rawLine).trimmingCharacters(in: .whitespacesAndNewlines)
                if line.hasPrefix("Hardware Port:") {
                    currentPort = line
                        .dropFirst("Hardware Port:".count)
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                } else if line.hasPrefix("Device:") {
                    let currentDevice = line
                        .dropFirst("Device:".count)
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    if let port = friendlyHardwarePort(currentPort) {
                        result[currentDevice] = port
                    }
                }
            }
            return result
        } catch {
            return [:]
        }
    }

    static func fallbackName(for device: String) -> String {
        let normalized = device.lowercased()
        if normalized.hasPrefix("bridge") { return "Network Bridge" }
        if normalized.hasPrefix("pdp_ip") { return "Mobile Network" }
        if normalized.hasPrefix("en") { return "Network Adapter" }
        return "Network"
    }

    private static func friendlyHardwarePort(_ value: String?) -> String? {
        guard let value, !value.isEmpty else { return nil }
        let normalized = value.lowercased()
        if normalized.contains("wi-fi") || normalized.contains("airport") { return "Wi‑Fi" }
        if normalized.contains("ethernet") { return "Ethernet" }
        if normalized.contains("thunderbolt") { return "Thunderbolt Network" }
        return value
    }
}

enum SystemProxyReader {
    static func current() -> SystemProxyState {
        guard let unmanaged = CFNetworkCopySystemProxySettings() else { return .direct }
        let dictionary = unmanaged.takeRetainedValue() as NSDictionary
        guard let values = dictionary as? [String: Any] else { return .direct }

        return SystemProxyState(
            socksEnabled: bool(values[kCFNetworkProxiesSOCKSEnable as String]),
            socksHost: string(values[kCFNetworkProxiesSOCKSProxy as String]),
            socksPort: integer(values[kCFNetworkProxiesSOCKSPort as String]),
            httpEnabled: bool(values[kCFNetworkProxiesHTTPEnable as String]),
            httpHost: string(values[kCFNetworkProxiesHTTPProxy as String]),
            httpPort: integer(values[kCFNetworkProxiesHTTPPort as String]),
            httpsEnabled: bool(values[kCFNetworkProxiesHTTPSEnable as String]),
            httpsHost: string(values[kCFNetworkProxiesHTTPSProxy as String]),
            httpsPort: integer(values[kCFNetworkProxiesHTTPSPort as String]),
            pacEnabled: bool(values[kCFNetworkProxiesProxyAutoConfigEnable as String]),
            pacURL: string(values[kCFNetworkProxiesProxyAutoConfigURLString as String]),
            autoDiscoveryEnabled: bool(values[kCFNetworkProxiesProxyAutoDiscoveryEnable as String])
        )
    }

    private static func bool(_ value: Any?) -> Bool {
        if let number = value as? NSNumber { return number.boolValue }
        if let value = value as? Bool { return value }
        if let value = value as? Int { return value != 0 }
        if let value = value as? String {
            return value == "1" || value.lowercased() == "true" || value.lowercased() == "yes"
        }
        return false
    }

    private static func integer(_ value: Any?) -> Int? {
        if let number = value as? NSNumber { return number.intValue }
        if let value = value as? Int { return value }
        if let value = value as? String { return Int(value) }
        return nil
    }

    private static func string(_ value: Any?) -> String? {
        if let value = value as? String { return value }
        if let value = value as? NSString { return value as String }
        return nil
    }
}
