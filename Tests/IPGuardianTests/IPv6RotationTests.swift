import XCTest
@testable import IPGuardian

/// macOS rotates the interface half of a temporary IPv6 address on a perfectly
/// healthy connection. Treating that as a connection change closed and killed
/// the protected applications, so these tests pin the behaviour down.
final class IPv6RotationTests: XCTestCase {
    private let directRoute =
        "proxy:direct/system-default|default4:en0|default6:en0|physical:en0|tunnels:none"

    func testRotatingPrivacyAddressInsideTheSameNetworkIsSafe() {
        XCTAssertEqual(
            SecurityDecision.evaluate(
                baseline: observation(ipv6: "2001:db8:85a3:1:a1b2:c3d4:e5f6:7890"),
                current: observation(ipv6: "2001:db8:85a3:1:9999:8888:7777:6666"),
                policy: .exactIP
            ),
            .safe
        )
    }

    func testMovingToADifferentIPv6NetworkIsUnsafe() {
        guard case .unsafe(let reasons) = SecurityDecision.evaluate(
            baseline: observation(ipv6: "2001:db8:85a3:1::1"),
            current: observation(ipv6: "2001:db8:85a3:2::1"),
            policy: .exactIP
        ) else {
            return XCTFail("A different IPv6 network must be unsafe")
        }
        XCTAssertTrue(reasons.contains { $0.contains("IPv6") })
    }

    func testIPv6AppearingWhereThereWasNoneIsUnsafe() {
        guard case .unsafe = SecurityDecision.evaluate(
            baseline: observation(ipv6: nil),
            current: observation(ipv6: "2001:db8:85a3:1::1"),
            policy: .exactIP
        ) else {
            return XCTFail("A new IPv6 path must be unsafe")
        }
    }

    func testSameCountryAllowsRotatingIPv4AndIPv6Together() {
        // The documented promise of Same Country: rotating addresses are fine
        // while the country and the route stay identical.
        XCTAssertEqual(
            SecurityDecision.evaluate(
                baseline: observation(ip: "91.15.203.44", ipv6: "2001:db8:1:2::5"),
                current: observation(ip: "91.15.203.45", ipv6: "2001:db8:1:2::9"),
                policy: .sameCountry,
                allowedCountries: ["DE"]
            ),
            .safe
        )
    }

    func testConfirmationTrackerTreatsARotatedAddressAsTheSameCandidate() {
        // The second route into a false Unsafe: if consecutive confirmation
        // checks look like different candidates, verification never settles.
        var tracker = ChangeConfirmationTracker()
        _ = tracker.register(
            observation(ipv6: "2001:db8:85a3:1::aaaa"),
            policy: .exactIP
        )
        _ = tracker.register(
            observation(ipv6: "2001:db8:85a3:1::bbbb"),
            policy: .exactIP
        )

        XCTAssertEqual(tracker.sightings, 2)
        XCTAssertEqual(tracker.completedConfirmationChecks, 1)
    }

    func testConfirmationTrackerRestartsWhenTheNetworkReallyChanges() {
        var tracker = ChangeConfirmationTracker()
        _ = tracker.register(
            observation(ipv6: "2001:db8:85a3:1::aaaa"),
            policy: .exactIP
        )
        _ = tracker.register(
            observation(ipv6: "2001:db8:85a3:2::aaaa"),
            policy: .exactIP
        )

        XCTAssertEqual(tracker.sightings, 1)
    }

    func testThreeMatchingSightingsStillConfirmAChange() {
        var tracker = ChangeConfirmationTracker()
        let changed = observation(ip: "51.158.145.12", ipv6: "2001:db8:85a3:9::1")
        XCTAssertFalse(tracker.register(changed, policy: .exactIP))
        XCTAssertFalse(tracker.register(changed, policy: .exactIP))
        XCTAssertTrue(tracker.register(changed, policy: .exactIP))
    }

    private func observation(
        ip: String = "91.15.203.44",
        ipv6: String?,
        country: String = "DE"
    ) -> IPObservation {
        IPObservation(
            ipv4: ip,
            ipv6: ipv6,
            directIPv6: nil,
            ipv6LeakStatus: .noLeakDetected,
            countryLabel: country,
            checkedAt: Date(),
            routeSignature: directRoute,
            proxySummary: "Direct"
        )
    }
}
