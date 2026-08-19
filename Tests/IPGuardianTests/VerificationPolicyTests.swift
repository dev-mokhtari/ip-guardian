import XCTest
@testable import IPGuardian

final class VerificationPolicyTests: XCTestCase {
    func testRetryTrackerStopsAfterExactlyThreeFailedRetries() {
        var tracker = RetryFailureTracker(maximumRetries: 3)

        XCTAssertFalse(tracker.recordFailedRetry())
        XCTAssertEqual(tracker.completedRetries, 1)
        XCTAssertFalse(tracker.recordFailedRetry())
        XCTAssertEqual(tracker.completedRetries, 2)
        XCTAssertTrue(tracker.recordFailedRetry())
        XCTAssertEqual(tracker.completedRetries, 3)
        XCTAssertTrue(tracker.recordFailedRetry())
        XCTAssertEqual(tracker.completedRetries, 3)
    }

    func testRetryTrackerResetStartsANewIncident() {
        var tracker = RetryFailureTracker(maximumRetries: 3)
        _ = tracker.recordFailedRetry()
        _ = tracker.recordFailedRetry()
        tracker.reset()
        XCTAssertEqual(tracker.completedRetries, 0)
    }

    func testIPConsensusAcceptsTwoMatchingProviders() {
        XCTAssertEqual(
            IPConsensus.selectIP(
                from: ["31.171.101.213", "217.218.152.246", "31.171.101.213"],
                minimumAgreement: 2
            ),
            "31.171.101.213"
        )
    }

    func testIPConsensusRejectsTwoDifferentStrongResults() {
        XCTAssertNil(
            IPConsensus.selectIP(
                from: ["31.171.101.213", "217.218.152.246"],
                minimumAgreement: 2
            )
        )
    }

    func testASingleProviderIsNeverEnoughForAnAddress() {
        XCTAssertNil(
            IPConsensus.selectIP(
                from: ["31.171.101.213"],
                minimumAgreement: 2
            )
        )
    }

    func testIPConsensusAcceptsTwoOfSixWithOtherFailuresOrOutliers() {
        XCTAssertEqual(
            IPConsensus.selectIP(
                from: [
                    "31.171.101.213",
                    "217.218.152.246",
                    "31.171.101.213"
                ],
                minimumAgreement: 2
            ),
            "31.171.101.213"
        )
    }

    func testIPConsensusRejectsATwoToTwoTie() {
        XCTAssertNil(
            IPConsensus.selectIP(
                from: [
                    "31.171.101.213",
                    "217.218.152.246",
                    "31.171.101.213",
                    "217.218.152.246"
                ],
                minimumAgreement: 2
            )
        )
    }

    func testCountryConsensusAcceptsTwoMatchingVotesWithOneOutlier() {
        XCTAssertEqual(
            CountryConsensus.selectCountry(
                from: ["DE", "FR", "de"],
                minimumAgreement: 2
            ),
            "DE"
        )
    }

    func testCountryConsensusIsIndependentOfResponseOrder() {
        let first = CountryConsensus.selectCountry(
            from: ["DE", "FR", "DE"],
            minimumAgreement: 2
        )
        let second = CountryConsensus.selectCountry(
            from: ["FR", "DE", "DE"],
            minimumAgreement: 2
        )

        XCTAssertEqual(first, "DE")
        XCTAssertEqual(second, "DE")
    }

    func testCountryConsensusRejectsATie() {
        XCTAssertNil(
            CountryConsensus.selectCountry(
                from: ["DE", "FR"],
                minimumAgreement: 1
            )
        )
    }

    func testProviderDiagnosticsAreNotExposedInUserMessage() {
        let error = IPServiceError.providerDisagreement(
            ["46.4.172.111", "167.233.0.197"],
            "AWS Check IP: success · ipify: SSL error"
        )

        XCTAssertFalse(error.userFacingDescription.contains("AWS"))
        XCTAssertFalse(error.userFacingDescription.contains("SSL"))
        XCTAssertTrue(error.errorDescription?.contains("AWS") == true)
    }

    func testCountryProviderDiagnosticsAreNotExposedInUserMessage() {
        let error = IPServiceError.insufficientCountryConsensus(
            "Cloudflare Trace: DE · Country.is: TLS error · ipapi.co: timed out"
        )

        XCTAssertFalse(error.userFacingDescription.contains("Country.is"))
        XCTAssertFalse(error.userFacingDescription.contains("Cloudflare"))
        XCTAssertFalse(error.userFacingDescription.contains("ipapi"))
        XCTAssertFalse(error.userFacingDescription.contains("TLS"))
        XCTAssertTrue(error.errorDescription?.contains("Country.is") == true)
    }
}
