// swift-tools-version: 5.9
import PackageDescription
let package = Package(name: "OpenLockSwift", products: [.library(name: "OpenLockSwift", targets: ["OpenLockSwift"])], targets: [.systemLibrary(name: "OpenLockFFI", path: "Sources/OpenLockFFI"), .target(name: "OpenLockSwift", dependencies: ["OpenLockFFI"])])
