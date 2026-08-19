import XCTest
@testable import IPGuardian

final class AllowedCountriesTests: XCTestCase {

    // MARK: - The list itself

    func testTheListIsNormalizedAndCapped() {
        XCTAssertEqual(AllowedCountries.normalized(["de", " GB ", "de", "fi", "nl"]),
                       ["DE", "GB", "FI"])
        XCTAssertEqual(AllowedCountries.normalized(["USA", "1R", ""]), [])
        XCTAssertEqual(AllowedCountries.maximumCount, 3)
    }

    func testACompleteListHasAtLeastOneCountry() {
        XCTAssertFalse(AllowedCountries.isComplete([]))
        XCTAssertFalse(AllowedCountries.isComplete(["USA"]))
        XCTAssertTrue(AllowedCountries.isComplete(["DE"]))
        XCTAssertTrue(AllowedCountries.isComplete(["DE", "GB", "FI"]))
    }

    func testMembershipIgnoresCaseAndPadding() {
        XCTAssertTrue(AllowedCountries.allows(" de ", in: ["DE", "GB"]))
        XCTAssertFalse(AllowedCountries.allows("SG", in: ["DE", "GB"]))
        XCTAssertFalse(AllowedCountries.allows(nil, in: ["DE"]))
    }

    // MARK: - What the votes are allowed to conclude

    func testTwoAgreeingSourcesInsideTheListConfirm() {
        XCTAssertEqual(
            CountryVerdict.evaluate(votes: ["DE", "DE"], allowedCountries: ["DE", "GB"]),
            .confirmed("DE")
        )
    }

    func testTwoPermittedCountriesTogetherDoNotConflict() {
        // Listing several countries is exactly the statement that seeing more
        // than one of them is fine.
        XCTAssertEqual(
            CountryVerdict.evaluate(votes: ["DE", "DE", "GB"], allowedCountries: ["DE", "GB"]),
            .confirmed("DE")
        )
    }

    func testOneSourceOutsideTheListIsNeverExcused() {
        // The hole this rule closes: two sources agreeing on Germany while a
        // third watched traffic leave from Singapore.
        XCTAssertEqual(
            CountryVerdict.evaluate(votes: ["DE", "DE", "SG"], allowedCountries: ["DE", "GB"]),
            .conflicting(["DE", "SG"])
        )
    }

    func testEverySourceAgreeingOnADisallowedCountryIsStillConfirmed() {
        // Confirmed, not permitted. SecurityDecision closes the apps; deciding
        // that here would skip the confirmation checks.
        XCTAssertEqual(
            CountryVerdict.evaluate(votes: ["SG", "SG"], allowedCountries: ["DE"]),
            .confirmed("SG")
        )
    }

    func testASingleSourceIsNotEnough() {
        XCTAssertEqual(
            CountryVerdict.evaluate(votes: ["DE"], allowedCountries: ["DE", "GB"]),
            .insufficient
        )
        XCTAssertEqual(
            CountryVerdict.evaluate(votes: [], allowedCountries: ["DE"]),
            .insufficient
        )
    }

    func testOnePermittedCountryEachIsNotAgreement() {
        // Both are allowed, but nothing reached two sources, so the country is
        // not established.
        XCTAssertEqual(
            CountryVerdict.evaluate(votes: ["DE", "GB"], allowedCountries: ["DE", "GB"]),
            .insufficient
        )
    }

    func testInvalidVotesAreIgnoredRatherThanCountedAgainst() {
        XCTAssertEqual(
            CountryVerdict.evaluate(votes: ["DE", "DE", "XX", "zzz"], allowedCountries: ["DE"]),
            .confirmed("DE")
        )
    }

    func testTheVerdictDoesNotDependOnResponseOrder() {
        let orders = [["DE", "GB", "DE"], ["GB", "DE", "DE"], ["DE", "DE", "GB"]]
        for order in orders {
            XCTAssertEqual(
                CountryVerdict.evaluate(votes: order, allowedCountries: ["DE", "GB"]),
                .confirmed("DE"),
                "\(order)"
            )
        }
    }

    // MARK: - Guarding the start

    func testAnEmptyListPermitsNothing() {
        // The reason Protection must not start without a saved list: with none,
        // every country fails and the apps would be closed within seconds of
        // Protection reporting itself active.
        for country in ["DE", "GB", "SG"] {
            XCTAssertFalse(AllowedCountries.allows(country, in: []), country)
        }
    }

    func testAConnectionOutsideTheListIsRecognisedBeforeItBecomesTheBaseline() {
        // Same question the start path asks before trusting the first
        // observation, so a refusal cannot silently turn into a baseline.
        XCTAssertFalse(AllowedCountries.allows("SG", in: ["DE"]))
        XCTAssertTrue(AllowedCountries.allows("DE", in: ["DE"]))
    }

    func testAnInvalidCodeNeverClaimsToHaveAFlag() {
        // Only the negative half is assertable here: the flags live in the app
        // bundle, and a test run's bundle is the test runner, not the app.
        XCTAssertFalse(CountryFlagImage.exists(for: "ZZZ"))
        XCTAssertFalse(CountryFlagImage.exists(for: "1R"))
        XCTAssertFalse(CountryFlagImage.exists(for: nil))
        XCTAssertEqual(CountryFlagImage.fileName(for: "IR"), "ir.png")
    }
}
