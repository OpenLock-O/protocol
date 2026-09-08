import SwiftUI

@main
struct OpenLockWatchApp: App {
    @StateObject private var controller = BluetoothController()
    @StateObject private var store = DoorStore()

    var body: some Scene {
        WindowGroup {
            DoorHomeView(controller: controller, store: store)
                .tint(.green)
        }
    }
}
