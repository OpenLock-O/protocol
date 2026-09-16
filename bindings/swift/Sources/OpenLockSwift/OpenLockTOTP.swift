import Foundation
import OpenLockFFI


/// Plaintext, unauthenticated result. Matching credentialID/timeStep only
/// correlates the response; it does not prove lock identity or physical opening.
public struct OpenLockResponse {
    public let credentialID: UInt32
    public let timeStep: UInt64
    public let errorCode: UInt32
}

/// Optional TOTP client in v3. BLE/NFC I/O and key storage are host-owned.
public enum OpenLock {
    public static func makeUnlock(secret: Data, credentialID: UInt32, unixSeconds: UInt64) throws -> Data {
        guard secret.count == 32, credentialID != 0 else { throw OpenLockError.code(3) }
        var buffer = [UInt8](repeating: 0, count: Int(OPENLOCK_REQUEST_SIZE))
        var length = 0
        let code = secret.withUnsafeBytes { key in
            openlock_make_unlock(key.bindMemory(to: UInt8.self).baseAddress, credentialID,
                                 unixSeconds, &buffer, buffer.count, &length)
        }
        guard code == 0 else { throw OpenLockError.code(code) }
        return Data(buffer[..<length])
    }

    /// Encode a code received through an authorized out-of-band path.
    public static func encodeUnlock(credentialID: UInt32, timeStep: UInt64, code: UInt32) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: Int(OPENLOCK_REQUEST_SIZE))
        var length = 0
        let result = openlock_encode_unlock(credentialID, timeStep, code, &buffer, buffer.count, &length)
        guard result == 0 else { throw OpenLockError.code(result) }
        return Data(buffer[..<length])
    }

    public static func decodeResponse(_ input: Data) throws -> OpenLockResponse {
        guard input.count == Int(OPENLOCK_RESPONSE_SIZE) else { throw OpenLockError.code(3) }
        var response = openlock_response_t()
        let code = input.withUnsafeBytes { bytes in
            openlock_decode_response(bytes.bindMemory(to: UInt8.self).baseAddress, input.count, &response)
        }
        guard code == 0 else { throw OpenLockError.code(code) }
        return OpenLockResponse(credentialID: response.credential_id,
                                timeStep: response.time_step, errorCode: response.error_code)
    }
}
