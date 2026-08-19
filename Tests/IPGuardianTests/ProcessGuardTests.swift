import XCTest
@testable import IPGuardian

final class ProcessGuardTests: XCTestCase {
    func testBundleIdentifierAloneDoesNotMatchAnotherApplicationPath() {
        let protected = ProtectedApp(
            name: "Protected",
            bundleIdentifier: "com.example.shared",
            path: "/Applications/Protected.app"
        )

        XCTAssertFalse(
            ProcessGuard.shared.isProtectedApplication(
                bundleIdentifier: "com.example.shared",
                bundlePath: "/Applications/Other.app",
                protectedApps: [protected]
            )
        )
    }

    func testBundleIdentifierAndExactPathMatchProtectedApplication() {
        let protected = ProtectedApp(
            name: "Protected",
            bundleIdentifier: "com.example.protected",
            path: "/Applications/Protected.app"
        )

        XCTAssertTrue(
            ProcessGuard.shared.isProtectedApplication(
                bundleIdentifier: "com.example.protected",
                bundlePath: "/Applications/Protected.app",
                protectedApps: [protected]
            )
        )
    }
}
