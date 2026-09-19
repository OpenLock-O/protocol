import Foundation
import OpenLockSwift

final class IntegrationTests {
    func testCompleteLifecycleAgainstRustDevice() throws {
        guard let path = ProcessInfo.processInfo.environment["OPENLOCK_SIMULATOR"] else { throw OpenLockError.malformed }
        let process = Process(); process.executableURL = URL(fileURLWithPath:path)
        let input = Pipe(),output = Pipe();process.standardInput = input;process.standardOutput = output;try process.run()
        defer { if process.isRunning {process.terminate()};process.waitUntilExit() }
        func line(_ request:String) throws -> String {
            input.fileHandleForWriting.write(Data((request+"\n").utf8));var data = Data()
            while true {let byte = output.fileHandleForReading.readData(ofLength:1);guard !byte.isEmpty else {throw OpenLockError.malformed};if byte[0] == 10 {break};data.append(byte)}
            let text = String(data:data,encoding:.utf8)!;XCTAssertFalse(text.hasPrefix("error:"),text);return text
        }
        func exchange(_ bytes:Data) throws -> Data {
            let text = try line(bytes.map {String(format:"%02x",$0)}.joined());let a = Array(text);var data = Data()
            for i in stride(from:0,to:a.count,by:2) {guard i+1<a.count,let byte = UInt8(String(a[i...i+1]),radix:16) else {throw OpenLockError.malformed};data.append(byte)};return data
        }
        let holder = Data(repeating:3,count:32),issuer = Data(repeating:9,count:32),lockID = Data(repeating:1,count:16)
        var publicKey = try OpenLockIssuer.publicKey(privateKey:Data(repeating:4,count:32),signing:false)
        func connect() throws -> OpenLockSession {XCTAssertEqual(try line("connect"),"ok");let s = try OpenLockSession(initiatorPrivateKey:holder,lockPublicKey:publicKey);_ = try s.receive(exchange(s.start()));return s}
        var session = try connect()
        let subject = try OpenLockIssuer.publicKey(privateKey:holder,signing:false)
        let grant = try OpenLockIssuer.issue(privateKey:issuer,credentialID:Data(repeating:2,count:16),lockID:lockID,subjectKey:subject,rights:2047,epoch:0)
        func request(_ action:LockAction,_ seq:UInt64 = 0,_ credential:Data? = nil) throws -> LockReply {
            let sent = try session.send(action,credential:credential ?? grant,sequence:seq)
            let received = try session.receive(exchange(sent.packet));guard case .response(let id,let response) = received.event else {throw OpenLockError.malformed}
            XCTAssertEqual(id,UInt64(sent.requestID));XCTAssertEqual(response.errorCode,0);guard let reply = response.reply else {throw OpenLockError.malformed};return reply
        }
        guard case .pairing(let epoch,_,true) = try request(.pairingStatus,0,Data()) else {return XCTFail("pairing")};XCTAssertEqual(epoch,0)
        _ = try request(.claim(setupKey:Data(repeating:7,count:32),issuer:OpenLockIssuer.publicKey(privateKey:issuer),adminCredential:grant),1,Data());session = try connect()
        guard case .operation(let operation) = try request(.unlock,1) else {return XCTFail("unlock")};XCTAssertEqual(operation.phase,.running)
        XCTAssertEqual(try line("complete-unlock"),"ok")
        guard case .status(let status) = try request(.status) else {return XCTFail("status")};if case .known(.unlocked) = status.bolt {} else {XCTFail("physical status")}
        _ = try request(.lock,2);XCTAssertEqual(try line("complete-lock"),"ok")
        _ = try request(.setConfig(DeviceConfig(version:1)),3)
        guard case .config(let config) = try request(.getConfig) else {return XCTFail("config")};XCTAssertEqual(config.version,1)
        guard case .audit(let audit) = try request(.readLog(after:0)) else {return XCTFail("audit")};XCTAssertFalse(audit.events.isEmpty)
        // SHA-256("abc"), a fixed cross-language image vector.
        let hash = Data([0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad])
        let manifest = FirmwareManifest(model:"reference-lock",hardware:"rev-a",version:"2.0",size:3,sha256:hash,securityVersion:1)
        let signed = try OpenLockIssuer.signFirmware(privateKey:Data(repeating:8,count:32),manifest:manifest)
        _ = try request(.firmwareBegin(signed),4);_ = try request(.firmwareChunk(offset:0,data:Data("abc".utf8)),5)
        _ = try request(.firmwareFinish,6);_ = try request(.firmwareActivate,7);XCTAssertEqual(try line("confirm-boot"),"ok")
        guard case .firmware(let firmware) = try request(.firmwareStatus) else {return XCTFail("firmware")};XCTAssertEqual(firmware.phase,.confirmed)
        let policy = try OpenLockIssuer.revoke(privateKey:issuer,lockID:lockID,epoch:0,version:1,credentials:[Data(repeating:5,count:16)])
        _ = try request(.applyPolicy(policy),8);_ = try request(.setClock(2000),9);_ = try request(.reboot,10)
        let newPublic = try OpenLockIssuer.publicKey(privateKey:Data(repeating:12,count:32),signing:false)
        let descriptor = DeviceKeyDescriptor(deviceID:lockID,keyID:2,keyVersion:2,publicKey:newPublic,rotationPublicKey:try OpenLockIssuer.publicKey(privateKey:Data(repeating:13,count:32)))
        let record = try OpenLockIssuer.signDeviceKey(privateKey:issuer,key:descriptor,issuerKeyID:1)
        let rotation = try OpenLockIssuer.signRotation(privateKey:issuer,oldKeyID:1,newRecord:record,notBefore:1900,retireAfter:2100,issuerKeyID:1)
        _ = try request(.rotateDeviceKey(rotation),11);publicKey = newPublic;session = try connect()
        XCTAssertEqual(try line("confirm-next"),"ok");_ = try request(.factoryReset,12)
        publicKey = try OpenLockIssuer.publicKey(privateKey:Data(repeating:4,count:32),signing:false);session = try connect()
        guard case .pairing(let newEpoch,_,false) = try request(.pairingStatus,0,Data()) else {return XCTFail("reset")};XCTAssertEqual(newEpoch,1)
    }
}

func XCTAssertEqual<T:Equatable>(_ a:@autoclosure () throws ->T,_ b:@autoclosure () throws ->T) {
    do {let lhs = try a(),rhs = try b();precondition(lhs == rhs,"values differ: \(lhs) versus \(rhs)")}catch{fatalError("\(error)")}
}
func XCTAssertFalse(_ value:Bool,_ message:String = "") {precondition(!value,message)}
func XCTFail(_ message:String) {fatalError(message)}
@main struct IntegrationMain {static func main() throws {try IntegrationTests().testCompleteLifecycleAgainstRustDevice();print("Swift device lifecycle passed")}}
