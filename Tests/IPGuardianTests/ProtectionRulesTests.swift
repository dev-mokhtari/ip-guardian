import XCTest
@testable import IPGuardian

final class ProtectionRulesTests: XCTestCase {

    // MARK: - Protection readiness

    func testReadyWhenAnAppIsSelectedAndNothingIsRunning() {
        XCTAssertNil(
            ProtectionReadiness.requirement(
                protectedAppCount: 1,
                runningProcessCount: 0,
                proxyConfigurationIncomplete: false
            )
        )
        XCTAssertTrue(
            ProtectionReadiness.canStart(
                protectedAppCount: 1,
                runningProcessCount: 0,
                proxyConfigurationIncomplete: false
            )
        )
    }

    func testAnEmptyApplicationListBlocksProtection() {
        XCTAssertEqual(
            ProtectionReadiness.requirement(
                protectedAppCount: 0,
                runningProcessCount: 0,
                proxyConfigurationIncomplete: false
            ),
            "Add at least one application to enable Protection."
        )
    }

    func testARunningProtectedApplicationBlocksProtection() {
        // Protection creates its baseline while the apps are closed; starting
        // with one already running would trust a connection it never checked.
        XCTAssertEqual(
            ProtectionReadiness.requirement(
                protectedAppCount: 1,
                runningProcessCount: 1,
                proxyConfigurationIncomplete: false
            ),
            "Close all protected applications before starting Protection."
        )
    }

    func testAnIncompleteProxyConfigurationBlocksProtection() {
        XCTAssertEqual(
            ProtectionReadiness.requirement(
                protectedAppCount: 1,
                runningProcessCount: 0,
                proxyConfigurationIncomplete: true
            ),
            "Complete the enabled Proxy configuration before starting Protection."
        )
    }

    func testTheMostBasicProblemIsReportedFirst() {
        XCTAssertEqual(
            ProtectionReadiness.requirement(
                protectedAppCount: 0,
                runningProcessCount: 3,
                proxyConfigurationIncomplete: true
            ),
            "Add at least one application to enable Protection."
        )
    }

    func testCanStartAlwaysAgreesWithTheStatedRequirement() {
        for apps in 0...2 {
            for running in 0...2 {
                for incomplete in [false, true] {
                    let requirement = ProtectionReadiness.requirement(
                        protectedAppCount: apps,
                        runningProcessCount: running,
                        proxyConfigurationIncomplete: incomplete
                    )
                    let canStart = ProtectionReadiness.canStart(
                        protectedAppCount: apps,
                        runningProcessCount: running,
                        proxyConfigurationIncomplete: incomplete
                    )
                    XCTAssertEqual(
                        canStart,
                        requirement == nil,
                        "apps=\(apps) running=\(running) incomplete=\(incomplete)"
                    )
                }
            }
        }
    }

    func testSameCountryCannotStartUntilTheListIsSaved() {
        XCTAssertEqual(
            ProtectionReadiness.requirement(
                protectedAppCount: 1,
                runningProcessCount: 0,
                proxyConfigurationIncomplete: false,
                needsAllowedCountries: true
            ),
            "Choose up to 3 allowed countries and save them before starting Protection."
        )
        XCTAssertNil(
            ProtectionReadiness.requirement(
                protectedAppCount: 1,
                runningProcessCount: 0,
                proxyConfigurationIncomplete: false,
                needsAllowedCountries: false
            )
        )
    }

    func testAnEmptyApplicationListIsStillReportedFirst() {
        XCTAssertEqual(
            ProtectionReadiness.requirement(
                protectedAppCount: 0,
                runningProcessCount: 0,
                proxyConfigurationIncomplete: false,
                needsAllowedCountries: true
            ),
            "Add at least one application to enable Protection."
        )
    }

    // MARK: - Turning Protection off

    func testAVerifiedConnectionMayLeaveApplicationsRunning() {
        // Ending a session must not cost the user their unsaved work.
        XCTAssertTrue(ProtectionShutdown.mayLeaveApplicationsRunning(mode: .protected))
    }

    func testEveryUnverifiedStateStillRequiresClosingTheApplications() {
        for mode in [GuardianMode.checking, .unverified, .unsafe] {
            XCTAssertFalse(
                ProtectionShutdown.mayLeaveApplicationsRunning(mode: mode),
                "\(mode) must not leave protected apps on an unvouched connection"
            )
        }
    }

    // MARK: - Same Country falling back to the trusted address

    func testAnUnchangedAddressIsAcceptedWhenTheCountryCannotBeSettled() {
        // Geo-IP databases disagree about VPN exits. That must not make the
        // relaxed policy stricter than Exact IP, which is satisfied here.
        XCTAssertTrue(
            TrustedAddressFallback.acceptsUnchangedAddress(
                consensusIPv4: "45.83.12.7",
                knownIPv4: "45.83.12.7"
            )
        )
    }

    func testAChangedAddressIsNotAcceptedOnItsOwn() {
        // Nothing is known about the new address, so an unsettled country stays
        // unverified.
        XCTAssertFalse(
            TrustedAddressFallback.acceptsUnchangedAddress(
                consensusIPv4: "91.20.5.44",
                knownIPv4: "45.83.12.7"
            )
        )
    }

    func testTheFallbackNeedsBothAddresses() {
        // No consensus address, or no baseline yet, means there is nothing to
        // compare and nothing to fall back on.
        XCTAssertFalse(
            TrustedAddressFallback.acceptsUnchangedAddress(
                consensusIPv4: nil,
                knownIPv4: "45.83.12.7"
            )
        )
        XCTAssertFalse(
            TrustedAddressFallback.acceptsUnchangedAddress(
                consensusIPv4: "45.83.12.7",
                knownIPv4: nil
            )
        )
        XCTAssertFalse(
            TrustedAddressFallback.acceptsUnchangedAddress(
                consensusIPv4: "45.83.12.7",
                knownIPv4: ""
            )
        )
    }

    // MARK: - Active application tally

    func testOnlyRunningAndPausedApplicationsAreCounted() {
        XCTAssertEqual(
            ProtectedAppTally.activeCount(states: [.running, .paused, .closed, .notProtected]),
            2
        )
        XCTAssertEqual(ProtectedAppTally.activeCount(states: []), 0)
        XCTAssertEqual(ProtectedAppTally.activeCount(states: [.closed, .closed]), 0)
    }

    // MARK: - Changed fields

    func testNothingIsReportedForAnIdenticalConnection() {
        let same = observation()
        XCTAssertEqual(
            ConnectionChangeSummary.changedFields(
                baseline: same,
                candidate: same,
                policy: .exactIP
            ),
            []
        )
    }

    func testRotatingIPv6InsideTheSameNetworkIsNotReported() {
        // The list must agree with SecurityDecision, which treats a privacy
        // address rotation as no change at all.
        XCTAssertEqual(
            ConnectionChangeSummary.changedFields(
                baseline: observation(ipv6: "2001:db8:1:2:aaaa:bbbb:cccc:dddd"),
                candidate: observation(ipv6: "2001:db8:1:2:1111:2222:3333:4444"),
                policy: .exactIP
            ),
            []
        )
    }

    func testADifferentIPv6NetworkIsReported() {
        XCTAssertEqual(
            ConnectionChangeSummary.changedFields(
                baseline: observation(ipv6: "2001:db8:1:2::1"),
                candidate: observation(ipv6: "2001:db8:1:9::1"),
                policy: .exactIP
            ),
            ["IPv6"]
        )
    }

    func testIPv4IsOnlyReportedUnderExactIP() {
        XCTAssertEqual(
            ConnectionChangeSummary.changedFields(
                baseline: observation(ip: "91.15.203.44"),
                candidate: observation(ip: "51.158.145.12"),
                policy: .exactIP
            ),
            ["Public IPv4"]
        )
        XCTAssertEqual(
            ConnectionChangeSummary.changedFields(
                baseline: observation(ip: "91.15.203.44"),
                candidate: observation(ip: "51.158.145.12"),
                policy: .sameCountry
            ),
            []
        )
    }

    func testCountryRouteAndLeakAreReportedTogether() {
        XCTAssertEqual(
            ConnectionChangeSummary.changedFields(
                baseline: observation(country: "DE", route: "direct/system-default"),
                candidate: observation(
                    country: "FR",
                    route: "socks5://127.0.0.1:1080",
                    leakStatus: .leakDetected
                ),
                policy: .sameCountry
            ),
            ["Country", "Route", "IPv6 leak"]
        )
    }

    func testCountryComparisonIgnoresCaseAndPadding() {
        XCTAssertEqual(
            ConnectionChangeSummary.changedFields(
                baseline: observation(country: "de"),
                candidate: observation(country: "  DE  "),
                policy: .sameCountry
            ),
            []
        )
    }

    private func observation(
        ip: String = "91.15.203.44",
        ipv6: String? = nil,
        country: String = "DE",
        route: String = "direct/system-default",
        leakStatus: IPv6LeakStatus = .noLeakDetected
    ) -> IPObservation {
        IPObservation(
            ipv4: ip,
            ipv6: ipv6,
            directIPv6: nil,
            ipv6LeakStatus: leakStatus,
            countryLabel: country,
            checkedAt: Date(),
            routeSignature: route,
            proxySummary: route
        )
    }
}
