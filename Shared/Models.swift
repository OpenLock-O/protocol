import Foundation
import Combine

struct Door: Identifiable, Codable, Equatable, Sendable {
    var id: UUID
    var name: String
    var openTime: Int = 650
    var waitTime: Int = 2000
    var closeTime: Int = 650
    var reverse: Bool = false
    var icon: DoorIcon?
    var tint: DoorTint?
    var coverData: Data?
    var location: DoorLocation?
    var isFavorite: Bool?
    var lastOpenedAt: Date?
}

enum DoorIcon: String, Codable, CaseIterable, Sendable {
    case door = "door.left.hand.closed", home = "house.fill", building = "building.2.fill"
    case office = "briefcase.fill", garage = "car.fill", key = "key.fill"
}

enum DoorTint: String, Codable, CaseIterable, Sendable {
    case green, blue, orange, pink, teal
}

struct DoorLocation: Codable, Equatable, Sendable {
    var latitude: Double
    var longitude: Double
}

struct DoorRecommendation: Equatable {
    let doorID: UUID
    let reason: String
}

struct NearbyDoor: Identifiable, Equatable, Sendable {
    let id: UUID
    let name: String
    let rssi: Int
    let battery: Int?
}

enum BluetoothAvailability: Equatable {
    case unknown, ready, poweredOff, unauthorized, unsupported
}

enum OperationState: Equatable {
    case idle, connecting, sending, waiting, succeeded, failed(String)
    var isBusy: Bool {
        switch self {
        case .connecting, .sending, .waiting: true
        default: false
        }
    }
}

// Implementations deliver all state changes on the main actor.
@MainActor
protocol DoorControlling: ObservableObject {
    var availability: BluetoothAvailability { get }
    var nearby: [NearbyDoor] { get }
    var isScanning: Bool { get }
    var operation: OperationState { get }
    var operationUpdates: AnyPublisher<OperationState, Never> { get }
    func scan()
    func stopScan()
    func unlock(_ door: Door, password: String)
    func changePassword(_ door: Door, oldPassword: String, newPassword: String)
    func cancel()
}
