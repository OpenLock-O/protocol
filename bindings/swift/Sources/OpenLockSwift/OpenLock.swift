import Foundation
import OpenLockFFI

func check(_ code:Int32) throws { if code != 0 { throw OpenLockError.code(code) } }
func output(_ call:(UnsafeMutablePointer<UInt8>,Int,UnsafeMutablePointer<Int>)->Int32) throws -> Data {
    var bytes = [UInt8](repeating:0,count:4096); var length = 0
    try check(call(&bytes,4096,&length)); return Data(bytes[..<length])
}
public struct LockAction {
    let wire:Wire
    public var opcode:UInt64 { if case .array(let a) = wire, case .uint(let n) = a[0] { return n }; return UInt64.max }
    private init(_ opcode:UInt64,_ args:[Wire] = []) { wire = .array([.uint(opcode)]+args) }
    init(wire:Wire) { self.wire = wire }
    public static let unlock = Self(0), status = Self(1), lock = Self(3), info = Self(4), getConfig = Self(6), reboot = Self(10), factoryReset = Self(11), firmwareFinish = Self(15), firmwareActivate = Self(16), firmwareAbort = Self(17), firmwareStatus = Self(18), credentialStatus = Self(20), pairingStatus = Self(22)
    public static func applyPolicy(_ signed:Data)->Self { Self(2,[.bytes(signed)]) }
    public static func operation(_ sequence:UInt64)->Self { Self(5,[.uint(sequence)]) }
    public static func setConfig(_ config:DeviceConfig)->Self { Self(7,[config.wire]) }
    public static func readLog(after:UInt64,limit:UInt64 = 16)->Self { Self(8,[.uint(after),.uint(limit)]) }
    public static func setClock(_ unixSeconds:UInt64)->Self { Self(9,[.uint(unixSeconds)]) }
    public static func replaceIssuer(_ publicKey:Data)->Self { Self(12,[.bytes(publicKey)]) }
    public static func firmwareBegin(_ signedManifest:Data)->Self { Self(13,[.bytes(signedManifest)]) }
    public static func firmwareChunk(offset:UInt64,data:Data)->Self { Self(14,[.uint(offset),.bytes(data)]) }
    public static func claim(setupKey:Data,issuer:Data,adminCredential:Data)->Self { Self(19,[.bytes(setupKey),.bytes(issuer),.bytes(adminCredential)]) }
    public static func rotateDeviceKey(_ signedUpdate:Data)->Self { Self(21,[.bytes(signedUpdate)]) }
}
public enum LockReply {
    case operation(OperationStatus), status(LockStatus), info(DeviceInfo), config(DeviceConfig), audit(AuditPage), firmware(FirmwareStatus)
    case claimed(epoch:UInt64,generation:UInt64), credential(uses:UInt64,maxUses:UInt64?,nextSequence:UInt64), pairing(epoch:UInt64,generation:UInt64,windowOpen:Bool)
    init(_ v:Wire) throws {
        let f = try v.fields(2)
        switch try f[0].number {
        case 0:self = .operation(try OperationStatus(f[1]));case 1:self = .status(try LockStatus(f[1]));case 2:self = .info(try DeviceInfo(f[1]));case 3:self = .config(try DeviceConfig(f[1]));case 4:self = .audit(try AuditPage(f[1]));case 5:self = .firmware(try FirmwareStatus(f[1]))
        case 6:let a = try f[1].fields(2);self = .claimed(epoch:try a[0].number,generation:try a[1].number)
        case 7:let a = try f[1].fields(3);self = .credential(uses:try a[0].number,maxUses:try a[1].optionalNumber,nextSequence:try a[2].number)
        case 8:let a = try f[1].fields(3);self = .pairing(epoch:try a[0].number,generation:try a[1].number,windowOpen:try a[2].bool)
        default:throw OpenLockError.malformed
        }
    }
}
public struct LockResponse {
    public let opcode:UInt64,errorCode:UInt64,reply:LockReply?
    init(_ v:Wire) throws {let f = try v.fields(3);opcode = try f[0].number;errorCode = try f[1].number;reply = errorCode == 0 ? try LockReply(f[2]):nil}
}
public enum SessionEvent {
    case handshake(peer:Data), request(id:UInt64,peer:Data,credential:Data,sequence:UInt64?,action:LockAction), response(id:UInt64,value:LockResponse)
    init(_ data:Data) throws {
        let f = try Wire.decode(data).fields(4)
        switch try f[0].number {
        case 1:self = .handshake(peer:try f[2].data)
        case 2:let c = try f[3].fields(3);self = .request(id:try f[1].number,peer:try f[2].data,credential:try c[0].data,sequence:try c[1].optionalNumber,action:LockAction(wire:c[2]))
        case 3:self = .response(id:try f[1].number,value:try LockResponse(f[3]))
        default:throw OpenLockError.malformed
        }
    }
}
/// Serialize calls on each session. Reconnect creates a new session; retain the
/// credential's operation sequence and query an ambiguous result before retrying.
public final class OpenLockSession {
    private var handle:OpaquePointer?
    public init(initiatorPrivateKey:Data,lockPublicKey:Data,capabilities:UInt64 = 8_388_607) throws {
        guard initiatorPrivateKey.count == 32,lockPublicKey.count == 32 else {throw OpenLockError.malformed}
        var h:OpaquePointer?
        let c = initiatorPrivateKey.withUnsafeBytes { p in lockPublicKey.withUnsafeBytes { q in openlock_session_initiator(p.bindMemory(to:UInt8.self).baseAddress,q.bindMemory(to:UInt8.self).baseAddress,capabilities,&h) } }
        try check(c);handle = h
    }
    deinit { if let handle { openlock_session_free(handle) } }
    public func start() throws -> Data {guard let handle else {throw OpenLockError.code(17)};return try output {openlock_session_start(handle,$0,$1,$2)} }
    public func send(_ action:LockAction,credential:Data = Data(),sequence:UInt64 = 0) throws -> (requestID:UInt32,packet:Data) {
        guard let handle else {throw OpenLockError.code(17)}
        let actionBytes = action.wire.encoded
        let command = try output { out,cap,len in credential.withUnsafeBytes { p in actionBytes.withUnsafeBytes { q in openlock_encode_command(p.bindMemory(to:UInt8.self).baseAddress,credential.count,sequence,q.bindMemory(to:UInt8.self).baseAddress,actionBytes.count,out,cap,len) } } }
        var id:UInt32 = 0
        let packet = try output {out,cap,len in command.withUnsafeBytes {p in openlock_session_send(handle,p.bindMemory(to:UInt8.self).baseAddress,command.count,&id,out,cap,len)} }
        return (id,packet)
    }
    public func receive(_ packet:Data) throws -> (event:SessionEvent?,reply:Data) {
        guard let handle else {throw OpenLockError.code(17)}
        try check(packet.withUnsafeBytes {openlock_session_receive(handle,$0.bindMemory(to:UInt8.self).baseAddress,packet.count)})
        let event = try output {openlock_session_take_event(handle,$0,$1,$2)}
        let reply = try output {openlock_session_take_output(handle,$0,$1,$2)}
        return (event.isEmpty ? nil : try SessionEvent(event),reply)
    }
}
public struct SetupPayload: CustomDebugStringConvertible {
    public let lockID:Data,publicKey:Data,setupKey:Data
    public var debugDescription:String {"SetupPayload(<redacted>)"}
    public init(qrText:String) throws {
        func hex(_ s:Substring,_ count:Int) throws -> Data {guard s.utf8.count == count*2, s.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {throw OpenLockError.malformed};var out = Data();let a = Array(s.utf8);for i in stride(from:0,to:a.count,by:2){guard let v = UInt8(String(bytes:a[i...i+1],encoding:.utf8)!,radix:16) else {throw OpenLockError.malformed};out.append(v)};return out}
        let f = qrText.split(separator:":",omittingEmptySubsequences:false);guard f.count == 4,f[0] == "OPENLOCK4" else {throw OpenLockError.malformed}
        lockID = try hex(f[1],16);publicKey = try hex(f[2],32);setupKey = try hex(f[3],32)
        guard setupKey != Data(repeating:0,count:32) else {throw OpenLockError.malformed}
    }
}
public enum OpenLockIssuer {
    public static let allRights:UInt64 = 2047
    public static func publicKey(privateKey:Data,signing:Bool = true) throws -> Data {
        guard privateKey.count == 32 else {throw OpenLockError.malformed};var out = [UInt8](repeating:0,count:32)
        try check(privateKey.withUnsafeBytes {openlock_public_key(signing ? 1:0,$0.bindMemory(to:UInt8.self).baseAddress,&out)});return Data(out)
    }
    static func sign(_ kind:UInt32,key:Data,payload:Wire) throws -> Data {
        guard key.count == 32 else {throw OpenLockError.malformed};let data = payload.encoded
        return try output {out,cap,len in key.withUnsafeBytes {k in data.withUnsafeBytes {p in openlock_sign(kind,k.bindMemory(to:UInt8.self).baseAddress,p.bindMemory(to:UInt8.self).baseAddress,data.count,out,cap,len)}}}
    }
    public static func issue(privateKey:Data,credentialID:Data,lockID:Data,subjectKey:Data,rights:UInt64,epoch:UInt64,validity:Range<UInt64>? = nil,maxUses:UInt64? = nil) throws -> Data {
        let v:Wire = validity.map {.array([.uint($0.lowerBound),.uint($0.upperBound)])} ?? .null
        return try sign(0,key:privateKey,payload:.array([.uint(2),.text("grant"),.bytes(credentialID),.bytes(lockID),.bytes(subjectKey),.uint(rights),.uint(epoch),v,maxUses.map(Wire.uint) ?? .null]))
    }
    public static func revoke(privateKey:Data,lockID:Data,epoch:UInt64,version:UInt64,credentials:[Data]) throws -> Data {
        let sorted = Array(Set(credentials)).sorted {$0.lexicographicallyPrecedes($1)}
        return try sign(1,key:privateKey,payload:.array([.uint(2),.text("policy"),.bytes(lockID),.uint(epoch),.uint(version),.array(sorted.map(Wire.bytes))]))
    }
    public static func signFirmware(privateKey:Data,manifest:FirmwareManifest) throws -> Data {try sign(2,key:privateKey,payload:manifest.wire)}
}

public struct DeviceKeyDescriptor {
    public let deviceID:Data,keyID:UInt64,keyVersion:UInt64,publicKey:Data,rotationPublicKey:Data,capabilities:UInt64
    public init(deviceID:Data,keyID:UInt64,keyVersion:UInt64,publicKey:Data,rotationPublicKey:Data,capabilities:UInt64 = 8_388_607) {self.deviceID = deviceID;self.keyID = keyID;self.keyVersion = keyVersion;self.publicKey = publicKey;self.rotationPublicKey = rotationPublicKey;self.capabilities = capabilities}
    func payload(_ issuerKeyID:UInt64)->Wire {.array([.uint(2),.bytes(deviceID),.uint(keyID),.uint(keyVersion),.bytes(publicKey),.bytes(rotationPublicKey),.uint(capabilities),.uint(issuerKeyID)])}
}
public struct SignedDeviceKey {public let key:DeviceKeyDescriptor,issuerKeyID:UInt64,signature:Data}
extension OpenLockIssuer {
    public static func signDeviceKey(privateKey:Data,key:DeviceKeyDescriptor,issuerKeyID:UInt64) throws -> SignedDeviceKey {SignedDeviceKey(key:key,issuerKeyID:issuerKeyID,signature:try sign(3,key:privateKey,payload:key.payload(issuerKeyID)))}
    public static func signRotation(privateKey:Data,oldKeyID:UInt64,newRecord:SignedDeviceKey,notBefore:UInt64,retireAfter:UInt64,issuerKeyID:UInt64?) throws -> Data {
        let payload:Wire = .array([.uint(2),.uint(oldKeyID),newRecord.key.payload(newRecord.issuerKeyID),.uint(notBefore),.uint(retireAfter),issuerKeyID.map(Wire.uint) ?? .null])
        let signature = try sign(4,key:privateKey,payload:payload)
        return Wire.array([.bytes(signature),.bytes(newRecord.signature)]).encoded
    }
}
