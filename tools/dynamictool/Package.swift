// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "dynamictool",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(name: "dynamictool", targets: ["dynamictool"])
    ],
    targets: [
        .executableTarget(
            name: "dynamictool",
            linkerSettings: [
                .linkedFramework("AppKit"),
                .linkedLibrary("EndpointSecurity"),
                .linkedLibrary("bsm")
            ]
        )
    ]
)
