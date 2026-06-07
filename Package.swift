// swift-tools-version: 6.0
// HankoSwift — Swift implementation of the Hanko v0.1 identity protocol.
//
// PROVENANCE: "Hanko" is the OBYW.one operator's own pre-existing internal
// codename, conceived independently. This package is gh:FJ-Studios/hanko-swift.
// Not related to teamhanko/hanko (a passkey project). See protocol/types.go.
//
// Companion to gh:FJ-Studios/hanko (Go reference implementation).
// All wire types mirror protocol/types.go v0.1 exactly.

import PackageDescription

let package = Package(
    name: "HankoSwift",
    platforms: [
        .macOS(.v14),
        .iOS(.v17),
    ],
    products: [
        .library(name: "HankoCore", targets: ["HankoCore"]),
    ],
    targets: [
        .target(
            name: "HankoCore",
            dependencies: [],
            path: "Sources/HankoCore"
        ),
    ]
)
