// swift-tools-version: 6.0
// PROVENANCE: "Hanko" is the OBYW.one operator's own pre-existing internal
// codename, conceived independently. See Sources/HankoCore/Protocol/Types.swift
// for the full provenance assertion.
import PackageDescription

let package = Package(
    name: "hanko-swift",
    platforms: [
        .macOS(.v14),
    ],
    products: [
        .library(name: "HankoCore", targets: ["HankoCore"]),
        .executable(name: "hanko", targets: ["HankoCLI"]),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "HankoCore",
            dependencies: [],
            path: "Sources/HankoCore"
        ),
        .executableTarget(
            name: "HankoCLI",
            dependencies: ["HankoCore"],
            path: "Sources/HankoCLI"
        ),
        .testTarget(
            name: "HankoCoreTests",
            dependencies: ["HankoCore"],
            path: "Tests/HankoCoreTests",
            resources: [
                .copy("TestVectors")
            ]
        ),
    ]
)
