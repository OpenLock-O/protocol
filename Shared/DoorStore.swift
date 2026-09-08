import Foundation
import Combine

@MainActor
final class DoorStore: ObservableObject {
    @Published private(set) var doors: [Door] = []
    @Published private(set) var loadError: String?
    private let defaults: UserDefaults
    private let credentials = CredentialStore()
    private let storageKey = "OpenLock.doors.v1"

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        if let data = defaults.data(forKey: storageKey) {
            do {
                let decoded = try JSONDecoder().decode([Door].self, from: data)
                guard Set(decoded.map(\.id)).count == decoded.count,
                      decoded.allSatisfy(Self.isValid) else { throw StoreError.invalidDoor }
                doors = decoded
            } catch {
                loadError = "无法读取已保存的门锁，原始数据已保留。请重启 App 后重试。"
            }
        }
    }

    static func validPassword(_ value: String) -> Bool {
        value.utf8.count == 6 && value.utf8.allSatisfy { (48...57).contains($0) }
    }

    func password(for door: Door) throws -> String {
        try credentials.password(for: door.id)
    }

    func save(_ door: Door, password: String? = nil) throws {
        guard loadError == nil else { throw StoreError.unavailable }
        guard Self.isValid(door) else { throw StoreError.invalidDoor }
        if let password, !Self.validPassword(password) { throw StoreError.invalidPassword }
        var updated = doors
        if let index = updated.firstIndex(where: { $0.id == door.id }) { updated[index] = door }
        else {
            guard password != nil else { throw StoreError.invalidPassword }
            updated.append(door)
        }
        let data = try JSONEncoder().encode(updated)
        if let password { try credentials.save(password, for: door.id) }
        defaults.set(data, forKey: storageKey)
        doors = updated
    }

    func savePassword(_ password: String, for door: Door) throws {
        guard Self.validPassword(password) else { throw StoreError.invalidPassword }
        try credentials.save(password, for: door.id)
    }

    func recordOpened(_ doorID: UUID) throws {
        guard loadError == nil else { throw StoreError.unavailable }
        guard var door = doors.first(where: { $0.id == doorID }) else { throw StoreError.invalidDoor }
        door.lastOpenedAt = Date()
        try save(door)
    }

    func delete(_ door: Door) throws {
        guard loadError == nil else { throw StoreError.unavailable }
        let updated = doors.filter { $0.id != door.id }
        let data = try JSONEncoder().encode(updated)
        try credentials.delete(for: door.id)
        defaults.set(data, forKey: storageKey)
        doors = updated
    }

    private static func isValid(_ door: Door) -> Bool {
        guard !door.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              [door.openTime, door.waitTime, door.closeTime].allSatisfy({ (0...10000).contains($0) }),
              (door.coverData?.count ?? 0) <= 2 * 1024 * 1024 else { return false }
        if let location = door.location {
            guard location.latitude.isFinite, location.longitude.isFinite,
                  (-90...90).contains(location.latitude), (-180...180).contains(location.longitude) else { return false }
        }
        if let date = door.lastOpenedAt, !date.timeIntervalSinceReferenceDate.isFinite { return false }
        return true
    }
}

private enum StoreError: LocalizedError {
    case invalidDoor, invalidPassword, unavailable
    var errorDescription: String? {
        switch self {
        case .invalidDoor: "请检查门锁名称、位置和封面，各项时间须为 0 到 10000 毫秒，封面不得超过 2 MB。"
        case .invalidPassword: "密码必须为 6 位数字。"
        case .unavailable: "门锁数据暂时不可用，请重启 App 后重试。"
        }
    }
}
