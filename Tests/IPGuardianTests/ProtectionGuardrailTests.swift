import XCTest
@testable import IPGuardian

final class ProtectionGuardrailTests: XCTestCase {
    func testLaunchdManagedInterfaceApplicationsAreRejected() {
        // launchd restarts these immediately, so closing one turns the Unsafe
        // path into a loop that never settles.
        for path in [
            "/System/Library/CoreServices/Finder.app",
            "/System/Library/CoreServices/Dock.app"
        ] {
            XCTAssertNotNil(
                GuardianController.unsupportedApplicationReason(
                    for: URL(fileURLWithPath: path)
                ),
                path
            )
        }
    }

    func testOrdinaryBundledAppleApplicationsAreAccepted() {
        // Calculator and Mail have no launchd job keeping them alive: they stay
        // closed like any other app, so refusing them was never justified.
        for path in [
            "/System/Applications/Calculator.app",
            "/System/Applications/Mail.app",
            "/System/Applications/Utilities/Terminal.app"
        ] {
            XCTAssertNil(
                GuardianController.unsupportedApplicationReason(
                    for: URL(fileURLWithPath: path)
                ),
                path
            )
        }
    }

    func testOrdinaryApplicationsAreAccepted() {
        XCTAssertNil(
            GuardianController.unsupportedApplicationReason(
                for: URL(fileURLWithPath: "/Applications/Safari.app")
            )
        )
        XCTAssertNil(
            GuardianController.unsupportedApplicationReason(
                for: URL(fileURLWithPath: "/Users/someone/Applications/Example.app")
            )
        )
    }

    func testAPathThatMerelyMentionsSystemIsAccepted() {
        XCTAssertNil(
            GuardianController.unsupportedApplicationReason(
                for: URL(fileURLWithPath: "/Applications/System Toolbox.app")
            )
        )
    }

    func testCooldownStartsOnlyAfterARateLimit() async {
        let cooldown = ProviderCooldown(firstDelay: 120, maximumDelay: 900)
        var resting = await cooldown.isResting("ipapi.co")
        XCTAssertFalse(resting)

        _ = await cooldown.recordRateLimit("ipapi.co")
        resting = await cooldown.isResting("ipapi.co")
        XCTAssertTrue(resting)
    }

    func testRepeatedRateLimitsBackOffButAreCapped() async {
        let start = Date()
        let cooldown = ProviderCooldown(firstDelay: 120, maximumDelay: 900)

        let first = await cooldown.recordRateLimit("ipapi.co", now: start)
        let second = await cooldown.recordRateLimit("ipapi.co", now: start)
        XCTAssertEqual(first.timeIntervalSince(start), 120, accuracy: 0.01)
        XCTAssertEqual(second.timeIntervalSince(start), 240, accuracy: 0.01)

        for _ in 0..<10 { _ = await cooldown.recordRateLimit("ipapi.co", now: start) }
        let capped = await cooldown.recordRateLimit("ipapi.co", now: start)
        XCTAssertEqual(capped.timeIntervalSince(start), 900, accuracy: 0.01)
    }

    func testCooldownExpiresAndSuccessClearsIt() async {
        let start = Date()
        let cooldown = ProviderCooldown(firstDelay: 120, maximumDelay: 900)
        _ = await cooldown.recordRateLimit("ipwho.is", now: start)

        var resting = await cooldown.isResting("ipwho.is", now: start.addingTimeInterval(119))
        XCTAssertTrue(resting)
        resting = await cooldown.isResting("ipwho.is", now: start.addingTimeInterval(121))
        XCTAssertFalse(resting)

        _ = await cooldown.recordRateLimit("ipwho.is", now: start)
        await cooldown.recordSuccess("ipwho.is")
        resting = await cooldown.isResting("ipwho.is", now: start)
        XCTAssertFalse(resting)
    }

    func testProvidersRestIndependently() async {
        let cooldown = ProviderCooldown(firstDelay: 120, maximumDelay: 900)
        _ = await cooldown.recordRateLimit("ipapi.co")

        let limited = await cooldown.isResting("ipapi.co")
        let other = await cooldown.isResting("ipwho.is")
        XCTAssertTrue(limited)
        XCTAssertFalse(other)
    }
}
