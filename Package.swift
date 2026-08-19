// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "IPGuardian",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "IPGuardian", targets: ["IPGuardian"])
    ],
    targets: [
        .executableTarget(
            name: "IPGuardian",
            path: "Sources/IPGuardian"
        ),
        .testTarget(
            name: "IPGuardianTests",
            dependencies: ["IPGuardian"],
            path: "Tests/IPGuardianTests"
        )
    ]
)
