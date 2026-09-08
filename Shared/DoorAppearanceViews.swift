import SwiftUI
#if os(iOS)
import PhotosUI
import ImageIO
import UIKit
#endif

extension DoorTint {
    var color: Color {
        switch self {
        case .green: .green
        case .blue: .blue
        case .orange: .orange
        case .pink: .pink
        case .teal: .teal
        }
    }
    var title: String {
        switch self {
        case .green: "绿色"
        case .blue: "蓝色"
        case .orange: "橙色"
        case .pink: "粉色"
        case .teal: "青色"
        }
    }
}

extension DoorIcon {
    var title: String {
        switch self {
        case .door: "门锁"
        case .home: "家"
        case .building: "楼宇"
        case .office: "办公室"
        case .garage: "车库"
        case .key: "钥匙"
        }
    }
}

struct DoorIdentityView: View {
    let door: Door
    var large = false
    var body: some View {
        Group {
            #if os(iOS)
            if let data = door.coverData, let image = UIImage(data: data) {
                Image(uiImage: image).resizable().scaledToFill()
            } else {
                symbol
            }
            #else
            symbol
            #endif
        }
        .frame(width: large ? 76 : 44, height: large ? 76 : 44)
        .background((door.tint ?? .green).color.opacity(0.12))
        .clipShape(RoundedRectangle(cornerRadius: 8))
        .accessibilityHidden(true)
    }
    private var symbol: some View {
        Image(systemName: (door.icon ?? .door).rawValue)
            .font(.system(size: large ? 34 : 22))
            .foregroundStyle((door.tint ?? .green).color)
    }
}

struct DoorAccessView: View {
    let door: Door
    let nearby: NearbyDoor?
    let busy: Bool
    let enabled: Bool
    let featured: Bool
    let result: String?
    let resultIsError: Bool
    var progress: String = "正在开门"
    let cancelTitle: String
    let unlock: () -> Void
    let cancel: () -> Void
    let details: () -> Void
    @Environment(\.dynamicTypeSize) private var dynamicTypeSize

    var body: some View {
        VStack(alignment: .leading, spacing: featured ? 18 : 12) {
            #if os(iOS)
            if featured, let data = door.coverData, let image = UIImage(data: data) {
                Image(uiImage: image)
                    .resizable().scaledToFill()
                    .frame(height: 180).frame(maxWidth: .infinity)
                    .clipped().clipShape(RoundedRectangle(cornerRadius: 8))
                    .accessibilityHidden(true)
            }
            #endif
            if isWatch || dynamicTypeSize.isAccessibilitySize {
                HStack {
                    DoorIdentityView(door: door)
                    Spacer(minLength: 0)
                    detailsButton
                }
                title
            } else {
                HStack(alignment: .center, spacing: 12) {
                    DoorIdentityView(door: door, large: featured)
                    title
                    Spacer(minLength: 0)
                    detailsButton
                }
            }
            Button(action: unlock) {
                HStack(spacing: 8) {
                    if busy { ProgressView().tint(.white) }
                    else { Image(systemName: "lock.open.fill") }
                    Text(busy ? progress : "开门").font(.headline)
                }
                .frame(maxWidth: .infinity, minHeight: featured && !isWatch ? 42 : 30)
            }
            .buttonStyle(.borderedProminent)
            .tint((door.tint ?? .green).color)
            .disabled(!enabled)
            .accessibilityLabel("打开\(door.name)")
            if busy {
                Button(cancelTitle, systemImage: "xmark", role: .cancel, action: cancel)
                    .buttonStyle(.borderless)
                    .frame(minHeight: 44)
                    .accessibilityLabel("\(cancelTitle)：\(door.name)")
            }
            if let result {
                Label(result, systemImage: resultIsError ? "exclamationmark.triangle.fill" : (result == "已取消" ? "minus.circle" : "checkmark.circle.fill"))
                    .font(.callout)
                    .foregroundStyle(resultIsError ? Color.red : Color.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(.vertical, featured ? 10 : 4)
    }
    private var detailsButton: some View {
        Button(action: details) { Image(systemName: "ellipsis.circle").font(.title3) }
            .buttonStyle(.borderless)
            .frame(minWidth: 44, minHeight: 44)
            .accessibilityLabel("\(door.name)的详情与设置")
            .help("门锁详情与设置")
    }
    private var title: some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(door.name).font(featured ? .title2.bold() : .headline)
                .fixedSize(horizontal: false, vertical: true)
            if door.isFavorite == true {
                Label("常用", systemImage: "star.fill").font(.caption).foregroundStyle(.secondary)
            }
            if let nearby {
                Label("附近", systemImage: "antenna.radiowaves.left.and.right")
                    .font(.caption).foregroundStyle(.secondary)
                if let battery = nearby.battery, battery <= 1 {
                    Label("电量较低", systemImage: "battery.25percent")
                        .font(.caption).foregroundStyle(.orange)
                }
            }
        }
    }
    private var isWatch: Bool {
        #if os(watchOS)
        true
        #else
        false
        #endif
    }
}

struct DoorAppearanceSettings: View {
    @Binding var door: Door
    @StateObject private var location = DoorLocationManager()
    @State private var awaitingLocation = false
    @State private var locationSaved = false
    #if os(iOS)
    @State private var selectedPhoto: PhotosPickerItem?
    @State private var photoError: String?
    @State private var loadingPhoto = false
    #endif

    var body: some View {
        Section("外观与常用") {
            HStack {
                DoorIdentityView(door: door, large: true)
                Text(door.name).font(.headline)
            }
            Toggle("设为常用门锁", isOn: Binding(get: { door.isFavorite ?? false }, set: { door.isFavorite = $0 }))
            Picker("图标", selection: Binding(get: { door.icon ?? .door }, set: { door.icon = $0 })) {
                ForEach(DoorIcon.allCases, id: \.self) { icon in
                    Label(icon.title, systemImage: icon.rawValue).tag(icon)
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("颜色")
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 40), spacing: 4)], spacing: 4) {
                ForEach(DoorTint.allCases, id: \.self) { tint in
                    Button { door.tint = tint } label: {
                        ZStack {
                            Circle().fill(tint.color).frame(width: 26, height: 26)
                            if (door.tint ?? .green) == tint {
                                Image(systemName: "checkmark").font(.caption.bold()).foregroundStyle(.white)
                            }
                        }.frame(minWidth: 32, minHeight: 44)
                    }
                    .buttonStyle(.borderless)
                    .accessibilityLabel(tint.title)
                    .accessibilityAddTraits((door.tint ?? .green) == tint ? .isSelected : [])
                }
                }
            }
            #if os(iOS)
            PhotosPicker(selection: $selectedPhoto, matching: .images) {
                Label(door.coverData == nil ? "选择封面照片" : "更换封面照片", systemImage: "photo")
            }
            if loadingPhoto { ProgressView("正在处理照片") }
            if let photoError { Text(photoError).foregroundStyle(.red) }
            if door.coverData != nil {
                Button("移除封面照片", systemImage: "photo.badge.minus", role: .destructive) {
                    selectedPhoto = nil
                    door.coverData = nil
                }
            }
            #endif
        }
        #if os(iOS)
        .task(id: selectedPhoto) {
            guard let selectedPhoto else { return }
            loadingPhoto = true
            photoError = nil
            defer { loadingPhoto = false }
            do {
                guard let data = try await selectedPhoto.loadTransferable(type: Data.self),
                      data.count <= 30_000_000,
                      let source = CGImageSourceCreateWithData(data as CFData, nil),
                      let thumbnail = CGImageSourceCreateThumbnailAtIndex(source, 0, [
                        kCGImageSourceCreateThumbnailFromImageAlways: true,
                        kCGImageSourceCreateThumbnailWithTransform: true,
                        kCGImageSourceThumbnailMaxPixelSize: 1200
                      ] as CFDictionary),
                      let jpeg = UIImage(cgImage: thumbnail).jpegData(compressionQuality: 0.8),
                      jpeg.count <= 2_000_000 else {
                    photoError = "这张照片无法用作封面，请选择另一张。"
                    return
                }
                try Task.checkCancellation()
                door.coverData = jpeg
            } catch is CancellationError {} catch {
                photoError = "未能读取照片，请重试。"
            }
        }
        #endif
        Section("门锁位置") {
            if door.location != nil {
                Label(locationSaved ? "已选定当前位置" : "已设置位置", systemImage: "location.fill")
            }
            Button {
                awaitingLocation = true
                location.requestLocation()
            } label: {
                Label(door.location == nil ? "使用当前位置" : "更新为当前位置", systemImage: "location")
            }
            .disabled(location.isLocating)
            if location.isLocating { ProgressView("正在获取位置") }
            if let message = location.message { Text(message).font(.caption).foregroundStyle(.secondary) }
            if door.location != nil {
                Button("移除位置", systemImage: "location.slash", role: .destructive) {
                    awaitingLocation = false
                    location.stop()
                    door.location = nil
                    locationSaved = false
                }
            }
        }
        .onChange(of: location.isLocating) { _, locating in
            guard !locating, awaitingLocation else { return }
            awaitingLocation = false
            if let current = location.currentLocation {
                door.location = current
                locationSaved = true
            }
        }
        .onDisappear { location.stop() }
    }
}
