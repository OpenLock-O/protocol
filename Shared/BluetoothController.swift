import Foundation
import Combine
import CoreBluetooth

@MainActor
final class BluetoothController: NSObject, DoorControlling, @preconcurrency CBCentralManagerDelegate {
    @Published private(set) var availability: BluetoothAvailability = .unknown
    @Published private(set) var nearby: [NearbyDoor] = []
    @Published private(set) var isScanning = false
    @Published private(set) var operation: OperationState = .idle

    var operationUpdates: AnyPublisher<OperationState, Never> {
        $operation.eraseToAnyPublisher()
    }

    private static let serviceID = CBUUID(string: "6E400001-B5A3-F393-E0A9-E50E24DCCA9E")
    private static let writeID = CBUUID(string: "6E400002-B5A3-F393-E0A9-E50E24DCCA9E")
    private static let notifyID = CBUUID(string: "6E400003-B5A3-F393-E0A9-E50E24DCCA9E")
    private var central: CBCentralManager!
    private var peripherals: [UUID: CBPeripheral] = [:]
    private var retiring: Set<UUID> = []
    private var session: Session?
    private var scanTimer: Task<Void, Never>?
    private var nearbyExpiryTimer: Task<Void, Never>?
    private var operationTimer: Task<Void, Never>?
    private var scanRequested = false

    override init() {
        super.init()
        central = CBCentralManager(delegate: self, queue: .main)
    }

    func scan() {
        guard !operation.isBusy else { return }
        guard availability == .ready else {
            scanRequested = availability == .unknown
            return
        }
        stopScan()
        nearbyExpiryTimer?.cancel()
        nearby = []
        isScanning = true
        central.scanForPeripherals(withServices: nil, options: [CBCentralManagerScanOptionAllowDuplicatesKey: true])
        scanTimer = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(6)) } catch { return }
            self?.stopScan()
        }
        nearbyExpiryTimer = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(30)) } catch { return }
            self?.nearby = []
        }
    }

    func stopScan() {
        scanRequested = false
        scanTimer?.cancel()
        scanTimer = nil
        central.stopScan()
        isScanning = false
    }

    func unlock(_ door: Door, password: String) {
        guard !operation.isBusy else { return }
        do { begin(door: door, packet: try YiLaProtocol.openCommand(door: door, password: password)) }
        catch { operation = .failed(error.localizedDescription) }
    }

    func changePassword(_ door: Door, oldPassword: String, newPassword: String) {
        guard !operation.isBusy else { return }
        do {
            begin(door: door, packet: try YiLaProtocol.changePasswordCommand(oldPassword: oldPassword, newPassword: newPassword))
        } catch { operation = .failed(error.localizedDescription) }
    }

    func cancel() {
        let commandWasSent = session?.phase == .response
        stopScan()
        releaseSession()
        operation = commandWasSent
            ? .failed("已停止等待，操作可能已执行，请检查门锁状态。")
            : .idle
    }

    private func begin(door: Door, packet: Data) {
        guard availability == .ready else {
            operation = .failed("蓝牙尚未就绪，请检查蓝牙开关和权限。")
            return
        }
        guard !retiring.contains(door.id) else {
            operation = .failed("上一次连接正在关闭，请稍后再试。")
            return
        }
        guard let peripheral = peripherals[door.id] ?? central.retrievePeripherals(withIdentifiers: [door.id]).first else {
            operation = .failed("找不到这扇门，请在附近重新扫描并添加。")
            return
        }
        stopScan()
        releaseSession()
        let current = Session(peripheral: peripheral, packet: packet, owner: self)
        session = current
        peripheral.delegate = current
        operation = .connecting
        armTimeout(seconds: 10, sessionID: current.id, message: "连接超时，请靠近门锁后重试。")
        central.connect(peripheral)
    }

    private func armTimeout(seconds: Int, sessionID: UUID, message: String) {
        operationTimer?.cancel()
        operationTimer = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(seconds)) } catch { return }
            guard let self, self.session?.id == sessionID else { return }
            self.finish(.failed(message))
        }
    }

    private func finish(_ result: OperationState) {
        releaseSession()
        operation = result
    }

    private func releaseSession() {
        operationTimer?.cancel()
        operationTimer = nil
        guard let current = session else { return }
        session = nil
        current.peripheral.delegate = nil
        current.packet = Data()
        if current.peripheral.state != .disconnected {
            // Do not reuse a peripheral until CoreBluetooth finishes cancellation.
            retiring.insert(current.peripheral.identifier)
            central.cancelPeripheralConnection(current.peripheral)
        }
    }

    func centralManagerDidUpdateState(_ central: CBCentralManager) {
        switch central.state {
        case .poweredOn: availability = .ready
        case .poweredOff: availability = .poweredOff
        case .unauthorized: availability = .unauthorized
        case .unsupported: availability = .unsupported
        case .unknown, .resetting: availability = .unknown
        @unknown default: availability = .unknown
        }
        if availability == .ready {
            if scanRequested { scan() }
        } else {
            nearbyExpiryTimer?.cancel()
            nearby = []
            let wantedScan = scanRequested
            stopScan()
            scanRequested = wantedScan && availability == .unknown
            if session != nil { finish(.failed("蓝牙连接已中断，请检查蓝牙开关和权限。")) }
            retiring.removeAll()
        }
    }

    func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral,
                        advertisementData: [String: Any], rssi RSSI: NSNumber) {
        guard isScanning else { return }
        let name = advertisementData[CBAdvertisementDataLocalNameKey] as? String ?? peripheral.name ?? ""
        guard name.uppercased().contains("YILA") else { return }
        let battery = (advertisementData[CBAdvertisementDataManufacturerDataKey] as? Data)
            .flatMap(YiLaProtocol.batteryFromManufacturerData)
        peripherals[peripheral.identifier] = peripheral
        let item = NearbyDoor(id: peripheral.identifier, name: name, rssi: RSSI.intValue, battery: battery)
        if let index = nearby.firstIndex(where: { $0.id == item.id }) { nearby[index] = item }
        else { nearby.append(item) }
        nearby.sort { $0.rssi > $1.rssi }
    }

    func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        if retiring.contains(peripheral.identifier) {
            central.cancelPeripheralConnection(peripheral)
            return
        }
        guard let current = session, current.peripheral === peripheral, current.phase == .connecting else { return }
        current.phase = .services
        peripheral.discoverServices([Self.serviceID])
    }

    func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        if retiring.remove(peripheral.identifier) != nil { return }
        guard session?.peripheral === peripheral else { return }
        finish(.failed("无法连接门锁，请靠近后重试。"))
    }

    func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        if retiring.remove(peripheral.identifier) != nil { return }
        guard session?.peripheral === peripheral else { return }
        finish(.failed("门锁连接已断开，未收到操作确认。"))
    }

    fileprivate func servicesDiscovered(_ current: Session, error: Error?) {
        guard session === current, current.phase == .services else { return }
        guard error == nil, let service = current.peripheral.services?.first(where: { $0.uuid == Self.serviceID }) else {
            finish(.failed("此设备未提供易拉门锁服务。")); return
        }
        current.phase = .characteristics
        current.peripheral.discoverCharacteristics([Self.writeID, Self.notifyID], for: service)
    }

    fileprivate func characteristicsDiscovered(_ current: Session, service: CBService, error: Error?) {
        guard session === current, current.phase == .characteristics, service.uuid == Self.serviceID else { return }
        guard error == nil,
              let write = service.characteristics?.first(where: { $0.uuid == Self.writeID }),
              let notify = service.characteristics?.first(where: { $0.uuid == Self.notifyID }),
              write.properties.contains(.writeWithoutResponse) || write.properties.contains(.write),
              notify.properties.contains(.notify) || notify.properties.contains(.indicate) else {
            finish(.failed("门锁的蓝牙通信接口不完整。")); return
        }
        current.write = write
        current.notify = notify
        current.writeType = write.properties.contains(.writeWithoutResponse) ? .withoutResponse : .withResponse
        current.phase = .notifying
        current.peripheral.setNotifyValue(true, for: notify)
    }

    fileprivate func notificationStateChanged(_ current: Session, characteristic: CBCharacteristic, error: Error?) {
        guard session === current, characteristic === current.notify else { return }
        guard error == nil, characteristic.isNotifying else {
            finish(.failed("无法接收门锁的操作确认。")); return
        }
        guard current.phase == .notifying else { return }
        current.phase = .readyToWrite
        operation = .sending
        armTimeout(seconds: 6, sessionID: current.id, message: "发送超时，门锁尚未确认操作。")
        writeIfReady(current)
    }

    fileprivate func writeIfReady(_ current: Session) {
        guard session === current, current.phase == .readyToWrite, let write = current.write else { return }
        guard current.packet.count <= current.peripheral.maximumWriteValueLength(for: current.writeType) else {
            finish(.failed("此连接无法一次发送完整指令，请重新连接后再试。")); return
        }
        if current.writeType == .withoutResponse && !current.peripheral.canSendWriteWithoutResponse { return }
        current.phase = .response
        operation = .waiting
        armTimeout(seconds: 6, sessionID: current.id, message: "未收到门锁确认，请检查门锁状态后再试。")
        current.peripheral.writeValue(current.packet, for: write, type: current.writeType)
        current.packet = Data()
    }

    fileprivate func writeCompleted(_ current: Session, characteristic: CBCharacteristic, error: Error?) {
        guard session === current, current.phase == .response, characteristic === current.write else { return }
        if error != nil { finish(.failed("指令发送失败，请检查门锁状态后再试。")) }
    }

    fileprivate func valueUpdated(_ current: Session, characteristic: CBCharacteristic, error: Error?) {
        guard session === current, current.phase == .response, characteristic === current.notify else { return }
        guard error == nil, let data = characteristic.value else {
            finish(.failed("读取门锁确认失败。")); return
        }
        let response = YiLaProtocol.parseResponse(data)
        if let battery = response.battery,
           let index = nearby.firstIndex(where: { $0.id == current.peripheral.identifier }) {
            let previous = nearby[index]
            nearby[index] = NearbyDoor(id: previous.id, name: previous.name, rssi: previous.rssi, battery: battery)
        }
        switch response.outcome {
        case .success: finish(.succeeded)
        case .rejected: finish(.failed("门锁拒绝了指令，请检查密码。"))
        case .unknown: break
        }
    }
}

// Each connection owns a delegate so queued callbacks cannot enter a later session.
@MainActor
fileprivate final class Session: NSObject, @preconcurrency CBPeripheralDelegate {
    enum Phase { case connecting, services, characteristics, notifying, readyToWrite, response }
    let id = UUID()
    let peripheral: CBPeripheral
    var packet: Data
    var phase: Phase = .connecting
    var write: CBCharacteristic?
    var notify: CBCharacteristic?
    var writeType: CBCharacteristicWriteType = .withoutResponse
    weak var owner: BluetoothController?

    init(peripheral: CBPeripheral, packet: Data, owner: BluetoothController) {
        self.peripheral = peripheral
        self.packet = packet
        self.owner = owner
    }

    func peripheral(_ peripheral: CBPeripheral, didDiscoverServices error: Error?) {
        owner?.servicesDiscovered(self, error: error)
    }
    func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        owner?.characteristicsDiscovered(self, service: service, error: error)
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        owner?.notificationStateChanged(self, characteristic: characteristic, error: error)
    }
    func peripheralIsReady(toSendWriteWithoutResponse peripheral: CBPeripheral) { owner?.writeIfReady(self) }
    func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        owner?.writeCompleted(self, characteristic: characteristic, error: error)
    }
    func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        owner?.valueUpdated(self, characteristic: characteristic, error: error)
    }
}
