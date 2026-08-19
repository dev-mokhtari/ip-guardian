import CFNetwork
import XCTest
@testable import IPGuardian

final class RouteIdentityTests: XCTestCase {
    func testVPNInterfaceIsPartOfRouteSignature() {
        let direct = NetworkRouteIdentity(
            proxySignature: "direct/system-default",
            defaultInterface: "en0",
            defaultIPv6Interface: "en0",
            tunnelInterfaces: [],
            proxyConfigured: false,
            proxyConfigurationIncomplete: false
        )
        let vpn = NetworkRouteIdentity(
            proxySignature: "direct/system-default",
            defaultInterface: "utun4",
            defaultIPv6Interface: "utun4",
            tunnelInterfaces: ["utun4"],
            proxyConfigured: false,
            proxyConfigurationIncomplete: false
        )

        XCTAssertNotEqual(direct.signature, vpn.signature)
    }

    func testPeripheralTunnelIsExcludedFromRouteIdentity() {
        XCTAssertEqual(
            NetworkRouteReader.routeRelevantTunnelInterfaces(
                defaultIPv4: "en0",
                defaultIPv6: "en0"
            ),
            []
        )
        XCTAssertEqual(
            NetworkRouteReader.routeRelevantTunnelInterfaces(
                defaultIPv4: "utun4",
                defaultIPv6: "en0"
            ),
            ["utun4"]
        )
    }

    func testPhysicalInterfaceIsPartOfRouteSignature() {
        let wifi = NetworkRouteIdentity(
            proxySignature: "direct/system-default",
            defaultInterface: "utun4",
            defaultIPv6Interface: "utun4",
            physicalInterface: "en0",
            tunnelInterfaces: ["utun4"],
            proxyConfigured: false,
            proxyConfigurationIncomplete: false
        )
        let ethernet = NetworkRouteIdentity(
            proxySignature: "direct/system-default",
            defaultInterface: "utun4",
            defaultIPv6Interface: "utun4",
            physicalInterface: "en5",
            tunnelInterfaces: ["utun4"],
            proxyConfigured: false,
            proxyConfigurationIncomplete: false
        )

        XCTAssertNotEqual(wifi.signature, ethernet.signature)
    }

    func testPhysicalInterfaceIsReadFromTheDefaultRouteTable() {
        let routeTable = """
        Destination        Gateway            Flags        Netif Expire
        default            link#22            UCSIg        utun4
        default            192.168.1.1        UGScg        en5
        """

        XCTAssertEqual(
            NetworkRouteReader.physicalInterface(
                fromRouteTable: routeTable,
                activeInterfaces: ["en0", "en5", "utun4"]
            ),
            "en5"
        )
    }

    func testAllEnabledProxyFieldsAffectRouteSignature() {
        let route = NetworkRouteIdentity(
            proxySignature: "socks5://127.0.0.1:1080|https-proxy://127.0.0.1:8080",
            defaultInterface: "en0",
            defaultIPv6Interface: "en0",
            tunnelInterfaces: [],
            proxyConfigured: true,
            proxyConfigurationIncomplete: false
        )

        XCTAssertTrue(route.signature.contains("socks5://127.0.0.1:1080"))
        XCTAssertTrue(route.signature.contains("https-proxy://127.0.0.1:8080"))
    }

    func testCombinedProxyDictionaryKeepsEveryEnabledRoute() {
        let proxy = SystemProxyState(
            socksEnabled: true,
            socksHost: "127.0.0.1",
            socksPort: 1080,
            httpEnabled: true,
            httpHost: "127.0.0.1",
            httpPort: 8080,
            httpsEnabled: true,
            httpsHost: "127.0.0.1",
            httpsPort: 8443,
            pacEnabled: false,
            pacURL: nil,
            autoDiscoveryEnabled: false
        )
        let dictionary = proxy.connectionProxyDictionary

        XCTAssertEqual(dictionary?[kCFNetworkProxiesSOCKSEnable as String] as? Int, 1)
        XCTAssertEqual(dictionary?[kCFNetworkProxiesHTTPEnable as String] as? Int, 1)
        XCTAssertEqual(dictionary?[kCFNetworkProxiesHTTPSEnable as String] as? Int, 1)
    }

    func testDashboardUsesFriendlyRouteNames() {
        let direct = NetworkRouteIdentity(
            proxySignature: "direct/system-default",
            defaultInterface: "en0",
            defaultIPv6Interface: "en0",
            physicalInterface: "en0",
            tunnelInterfaces: [],
            proxyConfigured: false,
            proxyConfigurationIncomplete: false
        )
        let vpn = NetworkRouteIdentity(
            proxySignature: "direct/system-default",
            defaultInterface: "utun4",
            defaultIPv6Interface: "utun4",
            physicalInterface: "en0",
            tunnelInterfaces: ["utun4"],
            proxyConfigured: false,
            proxyConfigurationIncomplete: false
        )
        let proxy = NetworkRouteIdentity(
            proxySignature: "socks5://127.0.0.1:1080",
            defaultInterface: "en0",
            defaultIPv6Interface: "en0",
            physicalInterface: "en0",
            tunnelInterfaces: [],
            proxyConfigured: true,
            proxyConfigurationIncomplete: false
        )

        XCTAssertEqual(direct.userFacingSummary, "Direct Connection")
        XCTAssertEqual(vpn.userFacingSummary, "VPN Tunnel")
        XCTAssertEqual(proxy.userFacingSummary, "Proxy Connection")
    }

    func testEnabledProxyWithoutHostOrPortIsIncomplete() {
        let proxy = SystemProxyState(
            socksEnabled: true,
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

        XCTAssertTrue(proxy.hasIncompleteConfiguration)
        XCTAssertFalse(proxy.hasAnyProxy)
    }

    func testVerificationRejectsARouteChangedDuringTheRequest() {
        let initial = NetworkRouteIdentity(
            proxySignature: "direct/system-default",
            defaultInterface: "utun4",
            defaultIPv6Interface: "utun4",
            physicalInterface: "en0",
            tunnelInterfaces: ["utun4"],
            proxyConfigured: false,
            proxyConfigurationIncomplete: false
        )
        let final = NetworkRouteIdentity(
            proxySignature: "direct/system-default",
            defaultInterface: "en0",
            defaultIPv6Interface: "en0",
            physicalInterface: "en0",
            tunnelInterfaces: [],
            proxyConfigured: false,
            proxyConfigurationIncomplete: false
        )

        XCTAssertFalse(
            IPService.routeRemainedStable(
                initialProxy: .direct,
                initialRoute: initial,
                finalProxy: .direct,
                finalRoute: final
            )
        )
    }
}
