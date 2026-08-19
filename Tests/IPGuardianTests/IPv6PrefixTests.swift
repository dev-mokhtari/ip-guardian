import XCTest
@testable import IPGuardian

final class IPv6PrefixTests: XCTestCase {
    func testRotatingPrivacyAddressKeepsTheSameNetwork() {
        // Two RFC 4941 temporary addresses from one /64: only the interface
        // identifier changes, which is what macOS rotates on a healthy link.
        let first = IPv6Prefix.network("2001:db8:85a3:1:a1b2:c3d4:e5f6:7890")
        let second = IPv6Prefix.network("2001:db8:85a3:1:1111:2222:3333:4444")

        XCTAssertNotNil(first)
        XCTAssertEqual(first, second)
    }

    func testDifferentNetworkIsDetected() {
        XCTAssertNotEqual(
            IPv6Prefix.network("2001:db8:85a3:1::1"),
            IPv6Prefix.network("2001:db8:85a3:2::1")
        )
    }

    func testCompressedAndExpandedFormsMatch() {
        XCTAssertEqual(
            IPv6Prefix.network("2001:0db8:0000:0000:0000:0000:0000:0001"),
            IPv6Prefix.network("2001:db8::1")
        )
    }

    func testZoneIndexIsIgnored() {
        XCTAssertEqual(
            IPv6Prefix.network("2001:db8::1%en0"),
            IPv6Prefix.network("2001:db8::1")
        )
    }

    func testInvalidInputIsRejected() {
        XCTAssertNil(IPv6Prefix.network(nil))
        XCTAssertNil(IPv6Prefix.network(""))
        XCTAssertNil(IPv6Prefix.network("   "))
        XCTAssertNil(IPv6Prefix.network("203.0.113.9"))
        XCTAssertNil(IPv6Prefix.network("not-an-address"))
    }

    func testUnparsableAddressStillComparesByItsText() {
        // The identity helper must never be weaker than a plain string match.
        XCTAssertEqual(SecurityDecision.ipv6Identity("garbage"), "garbage")
        XCTAssertNotEqual(
            SecurityDecision.ipv6Identity("garbage-a"),
            SecurityDecision.ipv6Identity("garbage-b")
        )
        XCTAssertNil(SecurityDecision.ipv6Identity(nil))
    }
}
