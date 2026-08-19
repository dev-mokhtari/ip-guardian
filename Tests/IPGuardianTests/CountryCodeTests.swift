import XCTest
@testable import IPGuardian

final class CountryCodeTests: XCTestCase {
    func testCountryCodeIsNormalized() {
        XCTAssertEqual(CountryCode.normalized("US"), "US")
        XCTAssertEqual(CountryCode.normalized("ir"), "IR")
    }

    func testInvalidCountryCodeIsRejected() {
        XCTAssertNil(CountryCode.normalized(nil))
        XCTAssertNil(CountryCode.normalized(""))
        XCTAssertNil(CountryCode.normalized("USA"))
        XCTAssertNil(CountryCode.normalized("1R"))
    }

    func testFlagFileNameUsesTheNormalizedLowercaseCode() {
        XCTAssertEqual(CountryFlagImage.fileName(for: "IR"), "ir.png")
        XCTAssertEqual(CountryFlagImage.fileName(for: " de "), "de.png")
        XCTAssertNil(CountryFlagImage.fileName(for: "invalid"))
        XCTAssertNil(CountryFlagImage.fileName(for: nil))
    }
}
