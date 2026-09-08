import Foundation
import Security

struct CredentialStore {
    private let service = "OpenLock.DoorPassword"

    func password(for id: UUID) throws -> String {
        var query = key(for: id)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw CredentialError(status: status) }
        guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
            throw CredentialError(status: errSecDecode)
        }
        return value
    }

    func save(_ password: String, for id: UUID) throws {
        let query = key(for: id)
        let attributes: [String: Any] = [kSecValueData as String: Data(password.utf8)]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = Data(password.utf8)
            item[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw CredentialError(status: addStatus) }
        } else if status != errSecSuccess {
            throw CredentialError(status: status)
        }
    }

    func delete(for id: UUID) throws {
        let status = SecItemDelete(key(for: id) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw CredentialError(status: status)
        }
    }

    private func key(for id: UUID) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: id.uuidString,
         kSecAttrSynchronizable as String: false]
    }
}

private struct CredentialError: LocalizedError {
    let status: OSStatus
    var errorDescription: String? {
        if status == errSecItemNotFound { return "未找到此门锁的密码，请在设置中重新保存。" }
        if status == errSecInteractionNotAllowed { return "请先解锁当前设备，再重试。" }
        return "无法访问安全保存的密码（\(status)）。请重试。"
    }
}
