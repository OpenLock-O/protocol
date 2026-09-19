import Foundation

public enum OpenLockError: Error { case code(Int32), malformed }
indirect enum Wire: Equatable {
    case uint(UInt64), bytes(Data), text(String), array([Wire]), null
    var encoded: Data {
        func head(_ major: UInt8, _ n: UInt64) -> Data {
            if n < 24 { return Data([major << 5 | UInt8(n)]) }
            let count = n <= 0xff ? 1 : n <= 0xffff ? 2 : n <= 0xffffffff ? 4 : 8
            var data = Data([major << 5 | (count == 1 ? 24 : count == 2 ? 25 : count == 4 ? 26 : 27)])
            for i in (0..<count).reversed() { data.append(UInt8(truncatingIfNeeded: n >> (i * 8))) }
            return data
        }
        switch self {
        case .uint(let n): return head(0,n)
        case .bytes(let d): return head(2,UInt64(d.count)) + d
        case .text(let s): let d = Data(s.utf8); return head(3,UInt64(d.count)) + d
        case .array(let a): return a.reduce(head(4,UInt64(a.count))) { $0 + $1.encoded }
        case .null: return Data([0xf6])
        }
    }
    static func decode(_ data: Data) throws -> Wire {
        let bytes = Array(data); var i = 0
        func byte() throws -> UInt8 { guard i < bytes.count else { throw OpenLockError.malformed }; defer { i += 1 }; return bytes[i] }
        func parse(_ depth: Int) throws -> Wire {
            guard depth < 32 else { throw OpenLockError.malformed }
            let h = try byte(); if h == 0xf6 { return .null }
            let ai = h & 31; var n = UInt64(ai)
            if ai >= 24 {
                let count: Int
                switch ai { case 24: count = 1; case 25: count = 2; case 26: count = 4; case 27: count = 8; default: throw OpenLockError.malformed }
                n = 0; for _ in 0..<count { n = (n << 8) | UInt64(try byte()) }
            }
            switch h >> 5 {
            case 0: return .uint(n)
            case 2,3:
                guard n <= UInt64(bytes.count - i) else { throw OpenLockError.malformed }
                let d = Data(bytes[i..<i+Int(n)]); i += Int(n)
                if h >> 5 == 2 { return .bytes(d) }; guard let s = String(data:d,encoding:.utf8) else { throw OpenLockError.malformed }; return .text(s)
            case 4:
                guard n <= 4096 else { throw OpenLockError.malformed }; var a:[Wire] = []
                for _ in 0..<Int(n) { a.append(try parse(depth+1)) }; return .array(a)
            default: throw OpenLockError.malformed
            }
        }
        guard data.count <= 4096 else { throw OpenLockError.malformed }
        let value = try parse(0); guard i == bytes.count && value.encoded == data else { throw OpenLockError.malformed }; return value
    }
    func fields(_ count: Int) throws -> [Wire] { guard case .array(let a) = self, a.count == count else { throw OpenLockError.malformed }; return a }
    var number: UInt64 { get throws { guard case .uint(let n) = self else { throw OpenLockError.malformed }; return n } }
    var data: Data { get throws { guard case .bytes(let d) = self else { throw OpenLockError.malformed }; return d } }
    var string: String { get throws { guard case .text(let s) = self else { throw OpenLockError.malformed }; return s } }
    var bool: Bool { get throws { let n = try number; guard n <= 1 else { throw OpenLockError.malformed }; return n == 1 } }
    var optionalNumber: UInt64? { get throws { self == .null ? nil : try number } }
}
public enum Reading<T> { case unsupported, unknown, known(T) }
func reading<T>(_ value:Wire,_ parse:(Wire)throws->T) throws -> Reading<T> {
    guard case .array(let a) = value, let tag = a.first else { throw OpenLockError.malformed }
    switch try tag.number {
    case 0: guard a.count == 1 else { throw OpenLockError.malformed }; return .unsupported
    case 1: guard a.count == 1 else { throw OpenLockError.malformed }; return .unknown
    case 2: guard a.count == 2 else { throw OpenLockError.malformed }; return .known(try parse(a[1]))
    default: throw OpenLockError.malformed
    }
}
func enumeration<T: RawRepresentable>(_ v:Wire,_ t:T.Type) throws -> T where T.RawValue == UInt64 {
    guard let result = T(rawValue:try v.number) else { throw OpenLockError.malformed }; return result
}
public enum BoltState: UInt64 { case locked, unlocked }
public enum DoorState: UInt64 { case closed, open }
public enum ActuatorKind: UInt64 { case motor, pulse }
public enum OperationPhase: UInt64 { case accepted, running, completed, failed, unknown }
public enum CompletionEvidence: UInt64 { case none, driver, sensor, noChange }
public enum LockFault: UInt64 { case none, jammed, timeout, sensorConflict, driver, doorAjar }
public enum FirmwarePhase: UInt64 { case empty, receiving, verified, trial, confirmed, failed }
public struct OperationStatus {
    public let credentialID:Data, sequence:UInt64, opcode:UInt64, phase:OperationPhase, evidence:CompletionEvidence, errorCode:UInt64
    init(_ v:Wire) throws { let f = try v.fields(6); credentialID = try f[0].data; sequence = try f[1].number; opcode = try f[2].number; phase = try enumeration(f[3],OperationPhase.self); evidence = try enumeration(f[4],CompletionEvidence.self); errorCode = try f[5].number }
}
public struct LockStatus {
    public let bolt:Reading<BoltState>, door:Reading<DoorState>, privacy:Reading<Bool>, batteryPercent:Reading<UInt64>
    public let fault:LockFault, active:OperationStatus?, epoch:UInt64, policyVersion:UInt64, configVersion:UInt64, generation:UInt64, clockTrusted:Bool
    init(_ v:Wire) throws { let f = try v.fields(11); bolt = try reading(f[0]) { try enumeration($0,BoltState.self) }; door = try reading(f[1]) { try enumeration($0,DoorState.self) }; privacy = try reading(f[2]) { try $0.bool }; batteryPercent = try reading(f[3]) { try $0.number }; fault = try enumeration(f[4],LockFault.self); active = f[5] == .null ? nil : try OperationStatus(f[5]); epoch = try f[6].number; policyVersion = try f[7].number; configVersion = try f[8].number; generation = try f[9].number; clockTrusted = try f[10].bool }
}
public enum AutoRelock {
    case disabled, delay(UInt64), afterClose(UInt64)
    var wire:Wire { switch self { case .disabled:return .array([.uint(0)]); case .delay(let n):return .array([.uint(1),.uint(n)]); case .afterClose(let n):return .array([.uint(2),.uint(n)]) } }
    init(_ v:Wire) throws { guard case .array(let a) = v, let first = a.first else { throw OpenLockError.malformed }; switch (try first.number,a.count) { case (0,1):self = .disabled; case (1,2):self = .delay(try a[1].number); case (2,2):self = .afterClose(try a[1].number); default:throw OpenLockError.malformed } }
}
public struct DeviceConfig {
    public var version:UInt64, autoRelock:AutoRelock, releaseMS:UInt64, actionTimeoutMS:UInt64, holdOpen:Bool, doorAjarMS:UInt64
    public init(version:UInt64,autoRelock:AutoRelock = .disabled,releaseMS:UInt64 = 500,actionTimeoutMS:UInt64 = 10000,holdOpen:Bool = false,doorAjarMS:UInt64 = 0) { self.version = version; self.autoRelock = autoRelock; self.releaseMS = releaseMS; self.actionTimeoutMS = actionTimeoutMS; self.holdOpen = holdOpen; self.doorAjarMS = doorAjarMS }
    var wire:Wire { .array([.uint(version),autoRelock.wire,.uint(releaseMS),.uint(actionTimeoutMS),.uint(holdOpen ? 1:0),.uint(doorAjarMS)]) }
    init(_ v:Wire) throws {let f = try v.fields(6);version = try f[0].number;autoRelock = try AutoRelock(f[1]);releaseMS = try f[2].number;actionTimeoutMS = try f[3].number;holdOpen = try f[4].bool;doorAjarMS = try f[5].number}
}
public struct FirmwareManifest {
    public let model:String, hardware:String, version:String, size:UInt64, sha256:Data, securityVersion:UInt64
    public init(model:String,hardware:String,version:String,size:UInt64,sha256:Data,securityVersion:UInt64) { self.model = model;self.hardware = hardware;self.version = version;self.size = size;self.sha256 = sha256;self.securityVersion = securityVersion }
    var wire:Wire { .array([.text(model),.text(hardware),.text(version),.uint(size),.bytes(sha256),.uint(securityVersion)]) }
    init(_ v:Wire) throws {let f = try v.fields(6);model = try f[0].string;hardware = try f[1].string;version = try f[2].string;size = try f[3].number;sha256 = try f[4].data;securityVersion = try f[5].number}
}
public struct FirmwareStatus {
    public let phase:FirmwarePhase, received:UInt64, manifest:FirmwareManifest?, securityVersion:UInt64
    init(_ v:Wire) throws { let f = try v.fields(4);phase = try enumeration(f[0],FirmwarePhase.self);received = try f[1].number;manifest = f[2] == .null ? nil : try FirmwareManifest(f[2]);securityVersion = try f[3].number }
}
public struct HardwareState {
    public let bolt:Reading<BoltState>,door:Reading<DoorState>,privacy:Reading<Bool>,batteryPercent:Reading<UInt64>
    init(_ v:Wire) throws {let f = try v.fields(4);bolt = try reading(f[0]) {try enumeration($0,BoltState.self)};door = try reading(f[1]) {try enumeration($0,DoorState.self)};privacy = try reading(f[2]) {try $0.bool};batteryPercent = try reading(f[3]) {try $0.number}}
}
public struct AuditEvent {
    public let cursor:UInt64, unixSeconds:UInt64?, kind:UInt64, credentialID:Data?, sequence:UInt64?, code:UInt64
    public let hardware:HardwareState?,operation:OperationStatus?
    init(_ v:Wire) throws { let f = try v.fields(8);cursor = try f[0].number;unixSeconds = try f[1].optionalNumber;kind = try f[2].number;credentialID = f[3] == .null ? nil : try f[3].data;sequence = try f[4].optionalNumber;code = try f[5].number;hardware = f[6] == .null ? nil : try HardwareState(f[6]);operation = f[7] == .null ? nil : try OperationStatus(f[7]) }
}
public struct AuditPage {
    public let events:[AuditEvent], nextCursor:UInt64, gap:Bool
    init(_ v:Wire) throws {let f = try v.fields(3);guard case .array(let a) = f[0] else {throw OpenLockError.malformed};events = try a.map(AuditEvent.init);nextCursor = try f[1].number;gap = try f[2].bool}
}

public struct DeviceInfo {
    public let lockID:Data
    public let model:String
    public let hardware:String
    public let firmware:String
    public let capabilities:UInt64
    public let actuator:ActuatorKind
    public let boltSensor:Bool
    public let doorSensor:Bool
    public let privacySensor:Bool
    public let batterySensor:Bool
    public let safeLockWithoutDoor:Bool
    public let holdOpen:Bool
    public let maxReleaseMS:UInt64
    public let maxActionMS:UInt64
    public let maxDelayMS:UInt64
    public let logCapacity:UInt64
    public let operationCapacity:UInt64
    public let credentialCapacity:UInt64
    public let maxImageSize:UInt64
    public let maxChunkSize:UInt64
    init(_ v:Wire) throws { let f = try v.fields(20)
        lockID = try f[0].data
        model = try f[1].string
        hardware = try f[2].string
        firmware = try f[3].string
        capabilities = try f[4].number
        actuator = try enumeration(f[5],ActuatorKind.self)
        boltSensor = try f[6].bool
        doorSensor = try f[7].bool
        privacySensor = try f[8].bool
        batterySensor = try f[9].bool
        safeLockWithoutDoor = try f[10].bool
        holdOpen = try f[11].bool
        maxReleaseMS = try f[12].number
        maxActionMS = try f[13].number
        maxDelayMS = try f[14].number
        logCapacity = try f[15].number
        operationCapacity = try f[16].number
        credentialCapacity = try f[17].number
        maxImageSize = try f[18].number
        maxChunkSize = try f[19].number
    }
}
