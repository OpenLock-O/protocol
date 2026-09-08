import Foundation
import OpenLockFFI

public enum OpenLockError: Error { case code(Int32) }
public final class OpenLockSession {
    private var handle: OpaquePointer?
    public init(initiatorPrivateKey: Data, lockPublicKey: Data, capabilities: UInt64) throws {
        guard initiatorPrivateKey.count == 32, lockPublicKey.count == 32 else { throw OpenLockError.code(-1) }
        var created: OpaquePointer?
        let code = initiatorPrivateKey.withUnsafeBytes { p in lockPublicKey.withUnsafeBytes { q in openlock_session_initiator(p.bindMemory(to: UInt8.self).baseAddress, q.bindMemory(to: UInt8.self).baseAddress, capabilities, &created) } }
        guard code == 0, let created else { throw OpenLockError.code(code) }; handle = created
    }
    deinit { if let handle { openlock_session_free(handle) } }
    public func start() throws -> Data {
        guard let handle else { throw OpenLockError.code(17) }; var buffer = [UInt8](repeating: 0, count: 4096); var length = 0
        let code = openlock_session_start(handle, &buffer, buffer.count, &length); guard code == 0 else { throw OpenLockError.code(code) }; return Data(buffer[..<length])
    }
}
