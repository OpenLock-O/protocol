// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OpenLockCore",
    platforms: [.macOS(.v13)],
    products: [.library(name: "OpenLockCore", targets: ["OpenLockCore"])],
    targets: [
        .target(
            name: "OpenLockCore",
            path: "Shared",
            exclude: [
                "BluetoothController.swift",
                "DoorStore.swift",
                "CredentialStore.swift",
                "DoorViews.swift",
                "DoorAppearanceViews.swift",
                "DoorLocationManager.swift"
            ],
            sources: ["Models.swift", "YiLaProtocol.swift", "DoorRecommendation.swift"]
        ),
        .testTarget(
            name: "OpenLockCoreTests",
            dependencies: ["OpenLockCore"],
            path: "Tests/OpenLockCoreTests"
        )
    ],
    swiftLanguageVersions: [.v5]
)
