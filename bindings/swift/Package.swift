// swift-tools-version: 5.9
import PackageDescription
let package = Package(
    name: "OpenLockSwift",
    platforms: [.macOS(.v14), .iOS(.v13)],
    products: [.library(name:"OpenLockSwift",targets:["OpenLockSwift"])],
    targets: [
        .systemLibrary(name:"OpenLockFFI",path:"Sources/OpenLockFFI"),
        .target(name:"OpenLockSwift",dependencies:["OpenLockFFI"],linkerSettings:[.linkedLibrary("openlock_ffi")]),
        .executableTarget(name:"OpenLockIntegration",dependencies:["OpenLockSwift"],path:"Tests/OpenLockSwiftTests")
    ]
)
