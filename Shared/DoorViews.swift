import SwiftUI
#if os(iOS)
import UIKit
#elseif os(watchOS)
import WatchKit
#endif

struct DoorHomeView<Controller: DoorControlling>: View {
    @ObservedObject var controller: Controller
    @ObservedObject var store: DoorStore
    @Environment(\.scenePhase) private var scenePhase
    @State private var showingDiscovery = false
    @State private var notice: String?
    @State private var pending: PendingOperation?
    @StateObject private var location = DoorLocationManager()
    #if os(iOS)
    @StateObject private var activity = UnlockActivityManager()
    #endif
    @State private var search = ""
    @State private var path: [UUID] = []
    @State private var focusedDoorID: UUID?
    @State private var resultDoorID: UUID?
    @State private var resultMessage: String?
    @State private var resultIsError = false
    @State private var recommendationSnapshot: DoorRecommendation?

    private enum PendingOperation {
        case unlock(Door)
        case password(Door, String)
    }

    var body: some View {
        NavigationStack(path: $path) {
            List {
                BluetoothStatusView(availability: controller.availability)
                if let error = store.loadError {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.red)
                } else if store.doors.isEmpty {
                    Section {
                        VStack(alignment: .leading, spacing: 12) {
                            Image(systemName: "door.left.hand.closed")
                                .font(.largeTitle).foregroundStyle(.green)
                            Text("还没有门锁").font(.headline)
                            Button("添加门锁", systemImage: "plus") { presentDiscovery() }
                                .disabled(controller.availability != .ready)
                        }
                        .padding(.vertical, 8)
                    }
                } else {
                    if search.isEmpty, let door = featuredDoor {
                        Section(recommendation?.reason ?? "常用门锁") {
                            DoorAccessView(door: door, nearby: nearby(door),
                                           busy: controller.operation.isBusy && resultDoorID == door.id,
                                           enabled: canUnlock, featured: true,
                                           result: resultDoorID == door.id ? resultMessage : nil,
                                           resultIsError: resultIsError,
                                           progress: operationMessage,
                                           cancelTitle: controller.operation == .waiting ? "停止等待" : "取消",
                                           unlock: { unlock(door) }, cancel: { controller.cancel() },
                                           details: { path.append(door.id) })
                        }
                    }
                    if !visibleDoors.isEmpty || !search.isEmpty {
                    Section(search.isEmpty ? "其他门锁" : "搜索结果") {
                        ForEach(visibleDoors) { door in
                            DoorAccessView(door: door, nearby: nearby(door),
                                           busy: controller.operation.isBusy && resultDoorID == door.id,
                                           enabled: canUnlock, featured: false,
                                           result: resultDoorID == door.id ? resultMessage : nil,
                                           resultIsError: resultIsError,
                                           progress: operationMessage,
                                           cancelTitle: controller.operation == .waiting ? "停止等待" : "取消",
                                           unlock: { unlock(door) }, cancel: { controller.cancel() },
                                           details: { path.append(door.id) })
                        }
                        if visibleDoors.isEmpty && !search.isEmpty {
                            Text("没有找到匹配的门锁").foregroundStyle(.secondary)
                        }
                    }
                    }
                }
                OperationStatusView(controller: controller)
            }
            .navigationTitle("OpenLock")
            #if os(iOS)
            .searchable(text: $search, prompt: "搜索门锁")
            #endif
            .navigationDestination(for: UUID.self) { id in
                DoorDetailView(controller: controller, store: store, doorID: id,
                               result: resultDoorID == id ? resultMessage : nil,
                               resultIsError: resultIsError,
                               unlock: unlock, changePassword: changePassword)
            }
            .toolbar {
                ToolbarItem(placement: .primaryAction) {
                    Button("刷新附近门锁", systemImage: "arrow.clockwise") {
                        refresh()
                        location.refreshIfAuthorized()
                    }
                        .disabled(controller.operation.isBusy || controller.isScanning || controller.availability != .ready)
                }
                ToolbarItem(placement: .primaryAction) {
                    Button("添加门锁", systemImage: "plus") { presentDiscovery() }
                        .disabled(controller.operation.isBusy || store.loadError != nil || controller.availability != .ready)
                }
            }
            .sheet(isPresented: $showingDiscovery, onDismiss: { refresh() }) {
                DiscoveryView(controller: controller, store: store)
            }
            .alert("OpenLock", isPresented: Binding(get: { notice != nil }, set: { if !$0 { notice = nil } })) {
                Button("好", role: .cancel) { notice = nil }
            } message: { Text(notice ?? "") }
        }
        .onChange(of: controller.operation) { _, state in
            #if os(iOS)
            if case .unlock = pending { activity.update(state) }
            #endif
            finish(state)
            if !state.isBusy { updateRecommendation() }
        }
        .onAppear {
            #if os(iOS)
            activity.observe(controller.operationUpdates)
            #endif
            updateRecommendation()
            refresh()
            location.refreshIfAuthorized()
        }
        .onChange(of: controller.isScanning) { _, scanning in if !scanning { updateRecommendation() } }
        .onChange(of: controller.nearby) { _, nearby in if nearby.isEmpty { updateRecommendation() } }
        .onChange(of: store.doors) { oldDoors, newDoors in
            let oldLocatedDoors = oldDoors.filter { $0.location != nil }
            let newLocatedDoors = newDoors.filter { $0.location != nil }
            let locationsChanged = oldLocatedDoors.count != newLocatedDoors.count || newLocatedDoors.contains { door in
                oldLocatedDoors.first(where: { $0.id == door.id })?.location != door.location
            }
            if locationsChanged && !newLocatedDoors.isEmpty {
                location.refreshIfAuthorized()
            }
            updateRecommendation()
        }
        .onChange(of: location.currentLocation) { _, _ in updateRecommendation() }
        .onChange(of: controller.availability) { _, state in if state == .ready { refresh() } }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background {
                controller.stopScan()
                location.stop()
                #if os(iOS)
                activity.beginBackgroundGracePeriod()
                #endif
            } else if phase == .active { refresh(); location.refreshIfAuthorized() }
        }
        .onOpenURL { url in
            guard url.scheme == "openlock", url.host == "door",
                  let id = UUID(uuidString: url.lastPathComponent),
                  store.doors.contains(where: { $0.id == id }) else { return }
            showingDiscovery = false
            path = [id]
        }
    }

    private var recommendation: DoorRecommendation? {
        recommendationSnapshot ?? DoorRecommendations.recommend(doors: store.doors, nearby: [], location: nil)
    }
    private func updateRecommendation() {
        guard !controller.operation.isBusy, !controller.isScanning else { return }
        recommendationSnapshot = DoorRecommendations.recommend(doors: store.doors, nearby: controller.nearby, location: location.currentLocation)
    }
    private var operationMessage: String {
        switch controller.operation {
        case .connecting: "正在连接"
        case .sending: "正在发送"
        case .waiting: "等待门锁确认"
        default: "正在开门"
        }
    }
    private var featuredDoor: Door? {
        let id = controller.operation.isBusy ? focusedDoorID : recommendation?.doorID
        return store.doors.first { $0.id == id } ?? store.doors.first
    }
    private var visibleDoors: [Door] {
        store.doors.filter { door in
            search.isEmpty ? door.id != featuredDoor?.id : door.name.localizedCaseInsensitiveContains(search)
        }
    }
    private var canUnlock: Bool { controller.availability == .ready && !controller.operation.isBusy && store.loadError == nil }
    private func nearby(_ door: Door) -> NearbyDoor? { controller.nearby.first { $0.id == door.id } }
    private func refresh() {
        guard scenePhase == .active, !showingDiscovery, !controller.operation.isBusy,
              !controller.isScanning, controller.availability == .ready else { return }
        controller.scan()
    }
    private func presentDiscovery() {
        controller.stopScan()
        showingDiscovery = true
    }

    private func unlock(_ door: Door) {
        guard !controller.operation.isBusy else { return }
        do {
            let password = try store.password(for: door)
            focusedDoorID = featuredDoor?.id
            resultDoorID = door.id
            resultMessage = nil
            resultIsError = false
            pending = .unlock(door)
            #if os(iOS)
            activity.start(door: door)
            #endif
            controller.unlock(door, password: password)
            #if os(iOS)
            activity.update(controller.operation)
            #endif
            if !controller.operation.isBusy { finish(controller.operation) }
        } catch { notice = error.localizedDescription }
    }

    private func changePassword(_ door: Door, _ password: String) -> Bool {
        guard !controller.operation.isBusy else { return false }
        do {
            let oldPassword = try store.password(for: door)
            focusedDoorID = featuredDoor?.id
            resultDoorID = door.id
            resultMessage = nil
            pending = .password(door, password)
            controller.changePassword(door, oldPassword: oldPassword, newPassword: password)
            if !controller.operation.isBusy { finish(controller.operation) }
            return true
        } catch { notice = error.localizedDescription; return false }
    }

    private func finish(_ state: OperationState) {
        guard let operation = pending else { return }
        switch state {
        case .succeeded:
            pending = nil
            switch operation {
            case .unlock(let door):
                resultMessage = "门锁已确认开门指令"
                resultIsError = false
                feedback(success: true)
                do { try store.recordOpened(door.id) }
                catch { notice = "开门指令已确认，但未能保存最近使用记录。\n\(error.localizedDescription)" }
            case .password(let door, let password):
                do {
                    try store.savePassword(password, for: door)
                    resultMessage = "门锁密码已修改并安全保存"
                    resultIsError = false
                    feedback(success: true)
                } catch {
                    notice = "设备密码已修改，但新密码未能保存。请在门锁设置中重新保存刚设置的密码。\n\(error.localizedDescription)"
                }
            }
        case .failed(let message):
            pending = nil
            if case .password = operation {
                notice = "\(message)\n若设备已执行修改但未能回传结果，请在设置中重新保存实际生效的密码。"
            } else {
                resultMessage = message
                resultIsError = true
                feedback(success: false)
            }
        case .idle:
            pending = nil
            if case .password = operation {
                notice = "修改已取消。若门锁已经执行修改，请在设置中重新保存实际生效的密码。"
            } else { resultMessage = "已取消" }
        case .connecting, .sending, .waiting: break
        }
    }

    private func feedback(success: Bool) {
        #if os(iOS)
        UINotificationFeedbackGenerator().notificationOccurred(success ? .success : .error)
        #elseif os(watchOS)
        WKInterfaceDevice.current().play(success ? .success : .failure)
        #endif
    }
}

private struct BluetoothStatusView: View {
    let availability: BluetoothAvailability
    var body: some View {
        if availability != .ready {
            Section {
                Label(message, systemImage: "antenna.radiowaves.left.and.right.slash")
                    .foregroundStyle(.secondary)
                #if os(iOS)
                if availability == .unauthorized, let url = URL(string: UIApplication.openSettingsURLString) {
                    Link("打开系统设置", destination: url)
                }
                #endif
            }
        }
    }
    private var message: String {
        switch availability {
        case .unknown: "正在检查蓝牙…"
        case .ready: "蓝牙已就绪"
        case .poweredOff: "蓝牙已关闭，请在系统设置中开启。"
        case .unauthorized: "蓝牙访问未获允许，请在系统设置中允许 OpenLock 使用蓝牙。"
        case .unsupported: "此设备不支持蓝牙门锁连接。"
        }
    }
}

private struct OperationStatusView<Controller: DoorControlling>: View {
    @ObservedObject var controller: Controller
    var body: some View {
        if controller.operation.isBusy {
            Section {
                HStack {
                    ProgressView()
                    Text(message)
                }
                Button(controller.operation == .waiting ? "停止等待" : "取消", systemImage: "xmark", role: .cancel) { controller.cancel() }
            }
        }
    }
    private var message: String {
        switch controller.operation {
        case .connecting: "正在连接门锁…"
        case .sending: "正在发送指令…"
        case .waiting: "正在等待设备确认…"
        default: ""
        }
    }
}

private struct DiscoveryView<Controller: DoorControlling>: View {
    @ObservedObject var controller: Controller
    @ObservedObject var store: DoorStore
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        NavigationStack {
            List {
                BluetoothStatusView(availability: controller.availability)
                Section("附近的门锁") {
                    ForEach(controller.nearby) { nearby in
                        if store.doors.contains(where: { $0.id == nearby.id }) {
                            Label(nearby.name + " · 已添加", systemImage: "checkmark.circle")
                                .foregroundStyle(.secondary)
                        } else {
                            NavigationLink {
                                AddDoorView(nearby: nearby, store: store) { dismiss() }
                            } label: {
                                VStack(alignment: .leading, spacing: 4) {
                                    Text(nearby.name).font(.headline)
                                    Text(nearby.id.uuidString.suffix(8)).font(.caption.monospaced())
                                        .foregroundStyle(.secondary)
                                    if let battery = nearby.battery {
                                        Label("电量等级 \(battery)/5", systemImage: "battery.100")
                                            .font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }
                        }
                    }
                    if controller.nearby.isEmpty {
                        Text(controller.isScanning ? "正在搜索附近的门锁…" : "未发现门锁")
                            .foregroundStyle(.secondary)
                    }
                }
                Button(controller.isScanning ? "停止搜索" : "搜索门锁",
                       systemImage: controller.isScanning ? "stop" : "arrow.clockwise") {
                    if controller.isScanning { controller.stopScan() } else { controller.scan() }
                }
                .disabled(controller.availability != .ready)
            }
            .navigationTitle("添加门锁")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("完成") { dismiss() } }
            }
        }
        .onAppear { if controller.availability == .ready { controller.scan() } }
        .onChange(of: controller.availability) { _, state in if state == .ready { controller.scan() } }
        .onDisappear { controller.stopScan() }
    }
}

private struct AddDoorView: View {
    let nearby: NearbyDoor
    @ObservedObject var store: DoorStore
    let completion: () -> Void
    @State private var name = ""
    @State private var password = ""
    @State private var error: String?
    var body: some View {
        Form {
            Section("门锁") { TextField("名称", text: $name) }
            Section("当前密码") { PasswordField(title: "6 位数字密码", text: $password) }
            if let error { Text(error).foregroundStyle(.red) }
            Button("添加", systemImage: "plus") {
                do {
                    try store.save(Door(id: nearby.id, name: name.trimmingCharacters(in: .whitespacesAndNewlines)), password: password)
                    password = ""
                    completion()
                } catch { self.error = error.localizedDescription }
            }
            .disabled(name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || !DoorStore.validPassword(password))
        }
        .navigationTitle("保存门锁")
        .onAppear { if name.isEmpty { name = nearby.name } }
    }
}

private struct DoorDetailView<Controller: DoorControlling>: View {
    @ObservedObject var controller: Controller
    @ObservedObject var store: DoorStore
    let doorID: UUID
    let result: String?
    let resultIsError: Bool
    let unlock: (Door) -> Void
    let changePassword: (Door, String) -> Bool

    var body: some View {
        if let door = store.doors.first(where: { $0.id == doorID }) {
            List {
                BluetoothStatusView(availability: controller.availability)
                Section {
                    HStack(spacing: 16) {
                        DoorIdentityView(door: door, large: true)
                        Text(door.name).font(.title2.bold())
                    }
                    Button("开门", systemImage: "lock.open.fill") { unlock(door) }
                    .buttonStyle(.borderedProminent)
                    .accessibilityLabel("打开\(door.name)")
                    .disabled(controller.availability != .ready || controller.operation.isBusy)
                    if let result {
                        Label(result, systemImage: resultIsError ? "exclamationmark.triangle" : (result == "已取消" ? "minus.circle" : "checkmark.circle"))
                            .foregroundStyle(resultIsError ? Color.red : Color.secondary)
                    }
                }
                OperationStatusView(controller: controller)
                Section {
                    NavigationLink {
                        DoorSettingsView(store: store, door: door)
                    } label: { Label("门锁设置", systemImage: "gearshape") }
                    .disabled(controller.operation.isBusy)
                    NavigationLink {
                        ChangePasswordView(door: door, submit: changePassword)
                    } label: { Label("修改门锁密码", systemImage: "key") }
                    .disabled(controller.operation.isBusy || controller.availability != .ready)
                }
            }
            .navigationTitle(door.name)
        } else {
            Text("门锁已移除").foregroundStyle(.secondary)
        }
    }
}

private struct DoorSettingsView: View {
    @ObservedObject var store: DoorStore
    @State var door: Door
    @Environment(\.dismiss) private var dismiss
    @State private var localPassword = ""
    @State private var error: String?
    @State private var confirmDelete = false
    var body: some View {
        Form {
            Section("名称") { TextField("门锁名称", text: $door.name) }
            DoorAppearanceSettings(door: $door)
            Section("开门动作") {
                TimingControl(title: "开门", value: $door.openTime)
                TimingControl(title: "等待", value: $door.waitTime)
                TimingControl(title: "关门", value: $door.closeTime)
                Toggle("反向转动", isOn: $door.reverse)
            }
            Section("已保存的密码") {
                PasswordField(title: "当前门锁密码", text: $localPassword)
                Button("重新保存密码", systemImage: "key") {
                    do {
                        try store.savePassword(localPassword, for: door)
                        localPassword = ""
                        error = "当前密码已安全保存。"
                    } catch { self.error = error.localizedDescription }
                }
                .disabled(!DoorStore.validPassword(localPassword))
            }
            if let error { Text(error).foregroundStyle(.secondary) }
            Button("移除门锁", systemImage: "trash", role: .destructive) { confirmDelete = true }
        }
        .navigationTitle("门锁设置")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("保存设置", systemImage: "checkmark") {
                    do {
                        door.name = door.name.trimmingCharacters(in: .whitespacesAndNewlines)
                        try store.save(door)
                        dismiss()
                    } catch { self.error = error.localizedDescription }
                }
                .labelStyle(.iconOnly)
                .accessibilityLabel("保存设置")
                .disabled(door.name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .confirmationDialog("从当前设备移除此门锁及保存的密码？", isPresented: $confirmDelete, titleVisibility: .visible) {
            Button("移除门锁", role: .destructive) {
                do { try store.delete(door); dismiss() }
                catch { self.error = error.localizedDescription }
            }
        }
    }
}

private struct TimingControl: View {
    let title: String
    @Binding var value: Int
    var body: some View {
        Stepper(value: $value, in: 0...10000, step: 50) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text("\(value) 毫秒").font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityValue("\(value) 毫秒")
    }
}

private struct ChangePasswordView: View {
    let door: Door
    let submit: (Door, String) -> Bool
    @Environment(\.dismiss) private var dismiss
    @State private var password = ""
    @State private var confirmation = ""
    @State private var confirmChange = false
    var body: some View {
        Form {
            Section("新密码") {
                PasswordField(title: "6 位数字密码", text: $password)
                PasswordField(title: "再次输入新密码", text: $confirmation)
            }
            Button("修改门锁密码", systemImage: "key") { confirmChange = true }
                .disabled(!DoorStore.validPassword(password) || password != confirmation)
        }
        .navigationTitle("修改密码")
        .confirmationDialog("修改后，其他设备需要使用新密码。", isPresented: $confirmChange, titleVisibility: .visible) {
            Button("确认修改") {
                if submit(door, password) {
                    password = ""
                    confirmation = ""
                    dismiss()
                }
            }
        }
    }
}

private struct PasswordField: View {
    let title: String
    @Binding var text: String
    var body: some View {
        #if os(iOS)
        SecureField(title, text: $text)
            .keyboardType(.numberPad)
            .textContentType(.password)
        #else
        SecureField(title, text: $text)
            .textContentType(.password)
        #endif
    }
}
