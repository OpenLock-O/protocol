import CommonCrypto
import Foundation
import XCTest
@testable import OpenLockCore

final class YiLaProtocolTests: XCTestCase {
    private let timestamp: Int64 = 1_700_000_000

    // Independent oracle: OpenSSL AES-128-ECB, -nopad, key 4678346b36415769764f734c45344e49;
    // UTF-8 timestamp + hashlib.md5(password).hexdigest()[8:24] + payload, zero-padded.
    func testCommandsMatchIndependentCiphertextVectors() throws {
        let vectors: [(ciphertext: Data, expectedHex: String)] = [
            (
                try YiLaProtocol.openCommand(door: Door(id: UUID(), name: "Door"), password: "123456", timestamp: timestamp),
                "1e0fc9fd88c18ed35e1e741c74bd58983e75d84a7b8b89eaba10dc1d6a31f4ad68154b59dcc763507cdf5fab992b1a741dd143adb2b87febe66989de87735eb8"
            ),
            (
                try YiLaProtocol.openCommand(
                    door: Door(id: UUID(), name: "Door", openTime: 0, waitTime: 10000, closeTime: 1, reverse: true),
                    password: "123456", timestamp: 0
                ),
                "1dfabff916b226af34fec7673d1915c60bf55e3571c98327a2d333e8b9ed20adeb4e072f9d84d74822be5f3deb2fb28e"
            ),
            (
                try YiLaProtocol.changePasswordCommand(oldPassword: "123456", newPassword: "654321", timestamp: timestamp),
                "1e0fc9fd88c18ed35e1e741c74bd5898746ab59b6e7fcb8794a5e932ee04ecccf61f127ba31f423a8336ef98847903b4f293473441417c62a65f8a1f4d648b73"
            )
        ]
        for vector in vectors {
            XCTAssertEqual(vector.ciphertext.map { String(format: "%02x", $0) }.joined(), vector.expectedHex)
        }
    }

    func testOpenCommandContainsReferencePayloadAndZeroPadding() throws {
        let door = Door(id: UUID(), name: "Front door")
        let encrypted = try YiLaProtocol.openCommand(door: door, password: "123456", timestamp: timestamp)
        let plaintext = try decrypt(encrypted)
        // MD5("123456") = e10adc3949ba59abbe56e057f20f883e.
        let expected = Data("170000000049ba59abbe56e057A:OPEN;P:+ 650,2000,650;".utf8)
        XCTAssertEqual(plaintext.prefix(expected.count), expected)
        XCTAssertEqual(encrypted.count, 64)
        XCTAssertTrue(plaintext.dropFirst(expected.count).allSatisfy { $0 == 0 })
    }

    func testReverseAndBoundaryTimingsAreEncoded() throws {
        let door = Door(id: UUID(), name: "Door", openTime: 0, waitTime: 10000, closeTime: 1, reverse: true)
        let encrypted = try YiLaProtocol.openCommand(door: door, password: "123456", timestamp: 0)
        let expected = Data("049ba59abbe56e057A:OPEN;P:- 0,10000,1;".utf8)
        XCTAssertEqual(try decrypt(encrypted).prefix(expected.count), expected)
    }

    func testPasswordChangeUsesDerivedNewPassword() throws {
        let encrypted = try YiLaProtocol.changePasswordCommand(oldPassword: "123456", newPassword: "123456", timestamp: timestamp)
        let expected = Data("170000000049ba59abbe56e057A:PW;P:49ba59abbe56e057;".utf8)
        let plaintext = try decrypt(encrypted)
        XCTAssertEqual(plaintext.prefix(expected.count), expected)
        XCTAssertTrue(plaintext.dropFirst(expected.count).allSatisfy { $0 == 0 })
    }

    func testRejectsInvalidCommandInputs() {
        let door = Door(id: UUID(), name: "Door")
        XCTAssertThrowsError(try YiLaProtocol.openCommand(door: door, password: ""))
        XCTAssertThrowsError(try YiLaProtocol.openCommand(door: door, password: "123456", timestamp: -1))
        for keyPath in [\Door.openTime, \Door.waitTime, \Door.closeTime] {
            for invalid in [-1, 10001] {
                var invalidDoor = door
                invalidDoor[keyPath: keyPath] = invalid
                XCTAssertThrowsError(try YiLaProtocol.openCommand(door: invalidDoor, password: "123456"))
            }
        }
        for password in ["", "12345", "1234567", "abcdef", "１２３４５６", "12345 "] {
            XCTAssertThrowsError(try YiLaProtocol.changePasswordCommand(oldPassword: "123456", newPassword: password))
            XCTAssertThrowsError(try YiLaProtocol.changePasswordCommand(oldPassword: password, newPassword: "123456"))
            XCTAssertThrowsError(try YiLaProtocol.openCommand(door: door, password: password))
        }
        XCTAssertThrowsError(try YiLaProtocol.changePasswordCommand(oldPassword: "", newPassword: "123456"))
        XCTAssertThrowsError(try YiLaProtocol.changePasswordCommand(oldPassword: "123456", newPassword: "123456", timestamp: -1))
    }

    func testAcknowledgementRequiresExactTokenAndFailureWins() {
        XCTAssertEqual(response("OK").outcome, .success)
        XCTAssertEqual(response("ok\r\n").outcome, .success)
        XCTAssertEqual(response("\0OK\r\n\0").outcome, .success)
        XCTAssertEqual(response("OK;BAT:3").outcome, .success)
        XCTAssertEqual(response("BATTERY=4;OK").outcome, .success)
        XCTAssertEqual(response("OK;BAT:3").battery, 3)
        XCTAssertEqual(response("OK;ERROR").outcome, .rejected)
        XCTAssertEqual(response("FAIL;OK").outcome, .rejected)
        for text in ["", "BROKEN", "NOT_OK", "NOT OK", "OKAY", "BATTERY:4", "POWER:5",
                     "Everything OK", "OK pending", "OK;BAT:6", "OK;BAT:30", "OK;BAT:3;pending"] {
            XCTAssertEqual(response(text).outcome, .unknown, text)
        }
        XCTAssertEqual(YiLaProtocol.parseResponse(Data([0x4f, 0xff, 0x4b])).outcome, .unknown)
    }

    func testBatteryNotificationsNeverAcknowledgeCommand() {
        for level in 1...5 {
            let parsed = YiLaProtocol.parseResponse(Data([UInt8(level)]))
            XCTAssertEqual(parsed.battery, level)
            XCTAssertEqual(parsed.outcome, .unknown)
        }
        XCTAssertEqual(response("BATTERY=4").battery, 4)
        XCTAssertEqual(response("PWR:2").battery, 2)
        XCTAssertNil(response("BAT:10").battery)
        XCTAssertNil(response("BAT:6").battery)
        XCTAssertNil(response("BAT:0").battery)
    }

    func testManufacturerDataExcludesCompanyIdentifierFromBattery() {
        XCTAssertNil(YiLaProtocol.batteryFromManufacturerData(Data()))
        XCTAssertNil(YiLaProtocol.batteryFromManufacturerData(Data([1, 5])))
        XCTAssertEqual(YiLaProtocol.batteryFromManufacturerData(Data([0xff, 0xff, 2, 0x01, 3])), 3)
        XCTAssertNil(YiLaProtocol.batteryFromManufacturerData(Data([0xff, 0xff, 3, 0])))
        XCTAssertNil(YiLaProtocol.batteryFromManufacturerData(Data([0xff, 0xff, 4, 0x01, 3])))
        XCTAssertNil(YiLaProtocol.batteryFromManufacturerData(Data([0xff, 0xff, 0, 0x01, 3])))
        XCTAssertEqual(YiLaProtocol.batteryFromManufacturerData(Data([0xff, 0xff, 2, 0x01, 9, 2, 0x02, 5])), 5)
    }

    private func response(_ text: String) -> YiLaProtocol.Response {
        YiLaProtocol.parseResponse(Data(text.utf8))
    }

    private func decrypt(_ data: Data) throws -> Data {
        let key = Array("Fx4k6AWivOsLE4NI".utf8)
        var output = [UInt8](repeating: 0, count: data.count)
        let capacity = output.count
        var written = 0
        let status = key.withUnsafeBytes { keyBytes in
            data.withUnsafeBytes { inputBytes in
                output.withUnsafeMutableBytes { outputBytes in
                    CCCrypt(CCOperation(kCCDecrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                            keyBytes.baseAddress, key.count, nil, inputBytes.baseAddress, data.count,
                            outputBytes.baseAddress, capacity, &written)
                }
            }
        }
        guard status == kCCSuccess else { throw NSError(domain: "TestDecryption", code: Int(status)) }
        return Data(output.prefix(written))
    }
}
