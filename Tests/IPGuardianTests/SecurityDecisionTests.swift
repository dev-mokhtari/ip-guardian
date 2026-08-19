import XCTest
@testable import IPGuardian

final class SecurityDecisionTests: XCTestCase {
    func testExactIPAcceptsIdenticalConnection() {
        XCTAssertEqual(
            SecurityDecision.evaluate(
                baseline: observation(ip: "91.15.203.44"),
                current: observation(ip: "91.15.203.44"),
                policy: .exactIP
            ),
            .safe
        )
    }

    func testExactIPRejectsConfirmedIPv4Change() {
        assertUnsafe(
            baseline: observation(ip: "91.15.203.44"),
            current: observation(ip: "51.158.145.12"),
            policy: .exactIP
        )
    }

    func testSameCountryAcceptsRotatingIPOnIdenticalRoute() {
        XCTAssertEqual(
            SecurityDecision.evaluate(
                baseline: observation(ip: "91.15.203.44", country: "DE"),
                current: observation(ip: "91.15.203.45", country: "DE"),
                policy: .sameCountry,
                allowedCountries: ["DE"]
            ),
            .safe
        )
    }

    func testSameCountryRejectsCountryChange() {
        assertUnsafe(
            baseline: observation(ip: "91.15.203.44", country: "DE"),
            current: observation(ip: "51.158.145.12", country: "FR"),
            policy: .sameCountry,
            allowedCountries: ["DE"]
        )
    }

    func testSameCountryStillRejectsRouteChange() {
        assertUnsafe(
            baseline: observation(ip: "91.15.203.44", route: "socks5://127.0.0.1:1080"),
            current: observation(ip: "91.15.203.45", route: "direct/system-default"),
            policy: .sameCountry,
            allowedCountries: ["DE"]
        )
    }

    func testSameCountryRejectsVPNDisconnectEvenWhenCountryAndIPStayValid() {
        assertUnsafe(
            baseline: observation(
                ip: "91.15.203.44",
                country: "DE",
                route: "proxy:direct/system-default|default4:utun4|default6:utun4|physical:en0|tunnels:utun4"
            ),
            current: observation(
                ip: "91.15.203.45",
                country: "DE",
                route: "proxy:direct/system-default|default4:en0|default6:en0|physical:en0|tunnels:none"
            ),
            policy: .sameCountry,
            allowedCountries: ["DE"]
        )
    }

    func testProxyIPv6LeakIsUnsafe() {
        assertUnsafe(
            baseline: observation(ip: "91.15.203.44"),
            current: observation(
                ip: "91.15.203.44",
                directIPv6: "2001:db8::1",
                leakStatus: .leakDetected
            ),
            policy: .exactIP
        )
    }

    func testInitialDetectionPlusTwoConfirmationsAreRequired() {
        let changed = observation(ip: "51.158.145.12", country: "FR")
        var tracker = ChangeConfirmationTracker()

        XCTAssertFalse(tracker.register(changed, policy: .exactIP))
        XCTAssertEqual(tracker.completedConfirmationChecks, 0)
        XCTAssertFalse(tracker.register(changed, policy: .exactIP))
        XCTAssertEqual(tracker.completedConfirmationChecks, 1)
        XCTAssertTrue(tracker.register(changed, policy: .exactIP))
        XCTAssertEqual(tracker.completedConfirmationChecks, 2)
    }

    func testContradictoryCandidateRestartsConfirmationCount() {
        var tracker = ChangeConfirmationTracker()
        _ = tracker.register(observation(ip: "51.158.145.12"), policy: .exactIP)
        _ = tracker.register(observation(ip: "51.158.145.12"), policy: .exactIP)

        XCTAssertFalse(
            tracker.register(observation(ip: "51.158.145.13"), policy: .exactIP)
        )
        XCTAssertEqual(tracker.completedConfirmationChecks, 0)
    }

    func testSameCountryConfirmationIgnoresRotatingIPv4() {
        var tracker = ChangeConfirmationTracker()

        XCTAssertFalse(
            tracker.register(
                observation(ip: "46.4.172.111", country: "FR"),
                policy: .sameCountry
            )
        )
        XCTAssertFalse(
            tracker.register(
                observation(ip: "167.233.0.197", country: "FR"),
                policy: .sameCountry
            )
        )
        XCTAssertTrue(
            tracker.register(
                observation(ip: "77.21.125.205", country: "FR"),
                policy: .sameCountry
            )
        )
        XCTAssertEqual(tracker.completedConfirmationChecks, 2)
    }

    func testExactIPConfirmationStillTracksIPv4() {
        let first = ChangeCandidateFingerprint(
            observation(ip: "46.4.172.111"),
            policy: .exactIP
        )
        let second = ChangeCandidateFingerprint(
            observation(ip: "167.233.0.197"),
            policy: .exactIP
        )

        XCTAssertNotEqual(first, second)
    }

    func testAnyCountryOnTheListIsAccepted() {
        for country in ["DE", "GB", "FI"] {
            XCTAssertEqual(
                SecurityDecision.evaluate(
                    baseline: observation(ip: "91.15.203.44", country: "DE"),
                    current: observation(ip: "51.158.145.12", country: country),
                    policy: .sameCountry,
                    allowedCountries: ["DE", "GB", "FI"]
                ),
                .safe,
                country
            )
        }
    }

    func testACountryOffTheListClosesTheApps() {
        assertUnsafe(
            baseline: observation(ip: "91.15.203.44", country: "DE"),
            current: observation(ip: "51.158.145.12", country: "SG"),
            policy: .sameCountry,
            allowedCountries: ["DE", "GB"]
        )
    }

    func testTheBaselineCountryNoLongerDecidesOnItsOwn() {
        // Starting in Germany and moving to Britain is the point of the list.
        XCTAssertEqual(
            SecurityDecision.evaluate(
                baseline: observation(ip: "91.15.203.44", country: "DE"),
                current: observation(ip: "51.158.145.12", country: "GB"),
                policy: .sameCountry,
                allowedCountries: ["DE", "GB"]
            ),
            .safe
        )
    }

    private func assertUnsafe(
        baseline: IPObservation,
        current: IPObservation,
        policy: IPChangePolicy,
        allowedCountries: [String] = [],
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        guard case .unsafe = SecurityDecision.evaluate(
            baseline: baseline,
            current: current,
            policy: policy,
            allowedCountries: allowedCountries
        ) else {
            XCTFail("Expected unsafe decision", file: file, line: line)
            return
        }
    }

    private func observation(
        ip: String,
        country: String = "DE",
        route: String = "socks5://127.0.0.1:1080",
        directIPv6: String? = nil,
        leakStatus: IPv6LeakStatus = .noLeakDetected
    ) -> IPObservation {
        IPObservation(
            ipv4: ip,
            ipv6: nil,
            directIPv6: directIPv6,
            ipv6LeakStatus: leakStatus,
            countryLabel: country,
            checkedAt: Date(),
            routeSignature: route,
            proxySummary: route == "direct/system-default" ? "Direct" : "SOCKS5 127.0.0.1:1080"
        )
    }
}
