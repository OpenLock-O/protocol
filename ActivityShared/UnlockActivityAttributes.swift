import ActivityKit
import Foundation

struct UnlockActivityAttributes: ActivityAttributes {
    struct ContentState: Codable, Hashable {
        var phase: Phase
    }

    enum Phase: String, Codable, Hashable {
        case connecting, sending, waiting, confirmed, failed, interrupted
    }

    let doorID: UUID
    let doorName: String
    let iconName: String
}
