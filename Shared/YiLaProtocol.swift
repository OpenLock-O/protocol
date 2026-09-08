import CommonCrypto
import Foundation

enum YiLaProtocol {
    enum Outcome: Equatable {
        case success, rejected, unknown
    }

    struct Response {
        let outcome: Outcome
        let battery: Int?
    }

    enum CommandError: LocalizedError {
        case invalidPassword, invalidNewPassword, invalidTiming, invalidTimestamp
        case encryptionFailed

        var errorDescription: String? {
            switch self {
            case .invalidPassword: return "设备密码必须为六位数字。"
            case .invalidNewPassword: return "新密码必须为六位数字。"
            case .invalidTiming: return "动作时间必须在 0 至 10000 毫秒之间。"
            case .invalidTimestamp: return "设备时间无效。"
            case .encryptionFailed: return "无法生成设备指令，请重试。"
            }
        }
    }

    static func openCommand(
        door: Door,
        password: String,
        timestamp: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> Data {
        guard [door.openTime, door.waitTime, door.closeTime].allSatisfy({ (0...10000).contains($0) }) else {
            throw CommandError.invalidTiming
        }
        let direction = door.reverse ? "-" : "+"
        let payload = "A:OPEN;P:\(direction) \(door.openTime),\(door.waitTime),\(door.closeTime);"
        return try command(password: password, payload: payload, timestamp: timestamp)
    }

    static func changePasswordCommand(
        oldPassword: String,
        newPassword: String,
        timestamp: Int64 = Int64(Date().timeIntervalSince1970)
    ) throws -> Data {
        guard validPassword(newPassword) else {
            throw CommandError.invalidNewPassword
        }
        return try command(
            password: oldPassword,
            payload: "A:PW;P:\(derivedKey(newPassword));",
            timestamp: timestamp
        )
    }

    static func parseResponse(_ data: Data) -> Response {
        let bytes = Array(data)
        let singleByteBattery = bytes.count == 1 && (1...5).contains(bytes[0]) ? Int(bytes[0]) : nil
        guard bytes.allSatisfy({ $0 == 0 || $0 == 9 || $0 == 10 || $0 == 13 || (32...126).contains($0) }),
              let rawText = String(data: data, encoding: .ascii) else {
            return Response(outcome: .unknown, battery: singleByteBattery)
        }
        let text = rawText.uppercased()
        let tokens = text.split(whereSeparator: { !$0.isLetter && !$0.isNumber && $0 != "_" })
        let battery = singleByteBattery ?? batteryInText(text)
        if tokens.contains("ERROR") || tokens.contains("FAIL") {
            return Response(outcome: .rejected, battery: battery)
        }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines.union(CharacterSet(charactersIn: "\0")))
        let batteryField = #"(?:BATTERY|BATT|BAT|POWER|PWR)[\s:=,]*[1-5]"#
        let delimiter = #"[;,\s]+"#
        let acknowledgement = #"\A(?:OK(?:"# + delimiter + batteryField + #")?|"# + batteryField + delimiter + #"OK)\z"#
        if trimmed.range(of: acknowledgement, options: .regularExpression) != nil {
            return Response(outcome: .success, battery: battery)
        }
        return Response(outcome: .unknown, battery: battery)
    }

    static func batteryFromManufacturerData(_ data: Data) -> Int? {
        // CoreBluetooth already removes the AD length and type, but keeps the company ID.
        let vendorBytes = Array(data.dropFirst(2))
        var offset = 0
        while offset + 2 < vendorBytes.count {
            let length = Int(vendorBytes[offset])
            guard length > 0 else { break }
            let end = offset + length + 1
            guard end <= vendorBytes.count else { return nil }
            if length > 1, (1...5).contains(vendorBytes[end - 1]) {
                return Int(vendorBytes[end - 1])
            }
            offset = end
        }
        return nil
    }

    private static func batteryInText(_ text: String) -> Int? {
        let pattern = #"\b(?:BATTERY|BATT|BAT|POWER|PWR)[\s:=,]*([1-5])(?![0-9])\b"#
        guard let expression = try? NSRegularExpression(pattern: pattern),
              let match = expression.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              let range = Range(match.range(at: 1), in: text) else { return nil }
        return Int(text[range])
    }

    private static func derivedKey(_ password: String) -> String {
        let bytes = Array(password.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_MD5_DIGEST_LENGTH))
        bytes.withUnsafeBytes { buffer in
            _ = CC_MD5(buffer.baseAddress, CC_LONG(bytes.count), &digest)
        }
        return digest[4..<12].map { String(format: "%02x", $0) }.joined()
    }

    private static func validPassword(_ password: String) -> Bool {
        password.utf8.count == 6 && password.utf8.allSatisfy { (48...57).contains($0) }
    }

    private static func command(password: String, payload: String, timestamp: Int64) throws -> Data {
        guard validPassword(password) else { throw CommandError.invalidPassword }
        guard timestamp >= 0 else { throw CommandError.invalidTimestamp }
        var plaintext = Array("\(timestamp)\(derivedKey(password))\(payload)".utf8)
        let remainder = plaintext.count % kCCBlockSizeAES128
        if remainder != 0 {
            plaintext.append(contentsOf: repeatElement(0, count: kCCBlockSizeAES128 - remainder))
        }
        let key = Array("Fx4k6AWivOsLE4NI".utf8)
        var encrypted = [UInt8](repeating: 0, count: plaintext.count)
        let capacity = encrypted.count
        var written = 0
        let status = key.withUnsafeBytes { keyBuffer in
            plaintext.withUnsafeBytes { inputBuffer in
                encrypted.withUnsafeMutableBytes { outputBuffer in
                    CCCrypt(
                        CCOperation(kCCEncrypt), CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionECBMode),
                        keyBuffer.baseAddress, key.count, nil,
                        inputBuffer.baseAddress, plaintext.count,
                        outputBuffer.baseAddress, capacity, &written
                    )
                }
            }
        }
        guard status == kCCSuccess, written == plaintext.count else { throw CommandError.encryptionFailed }
        return Data(encrypted.prefix(written))
    }
}
