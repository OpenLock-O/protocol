# OpenLock

用于易拉门禁的原生 SwiftUI App，支持 iOS 17+ 和 watchOS 10+，参考 [OpenYiLa](https://github.com/JustaSage/OpenYiLa) 实现 BLE 协议。

支持发现附近设备、保存门禁、开门、修改设备密码，以及调整开门 / 等待 / 关门时长和方向。iPhone 和 Apple Watch 分别直接连接门禁，各自在本机添加设备、保存密码；目前不跨设备同步。设备密码需要 6 位 ASCII 数字。请仅连接你有权使用的门禁。

## 开发环境

自由开发工具由 Nix + devenv 提供；Xcode、Apple SDK、模拟器及签名证书使用系统安装。先安装并启动 Xcode，接受许可并安装需要的平台组件，然后进入项目：

```sh
devenv shell
task generate
open OpenLock.xcodeproj
```

`devenv.nix` 保留所给的 Git、glab、go-task、Python、平台工具及 Node.js 24 配置，并增加 Darwin 上的 XcodeGen。App 本身不依赖 JavaScript、Python 或 CocoaPods。`apple.sdk = null`，Darwin shell 清除 `AR`、`CC`、`CXX`、`LD`，以免 Nix 编译器包装器覆盖 Xcode 工具链。

```sh
devenv test
task test
task build-ios
task build-watch
```

`project.yml` 是 Xcode 工程的配置来源，变更后运行 `task generate`。仓库同时提供生成的工程供 Xcode 直接打开。真机运行时，在 App、Watch 和 Widget target 的 Signing & Capabilities 中选择自己的 Development Team，并按需修改唯一 Bundle Identifier；Watch 的 companion identifier 必须与 iOS identifier 一致，Widget identifier 应以 App identifier 为前缀。

构建任务使用专用 `Simulator` 配置，为 iOS 与 Watch 分别选择对应 SDK；无需安装 watchOS 模拟器运行时即可编译。Xcode 中真机运行使用 `Debug`，发行使用 `Release`。要启动 Watch 模拟器，仍需在 Xcode 设置中安装 watchOS 运行时。

## 使用

1. 在 iPhone 或 Watch 上打开 App，授予蓝牙权限。
2. 添加门禁，扫描附近广播名称中包含 `YILA` 的设备，输入设备的现有密码并保存。
3. 在首页点按门锁的开门按钮；连接、等待确认和结果会直接显示。只有收到设备确认，才显示成功。
4. 点门锁旁的详情按钮进入设置，可以修改名称、图标、颜色、常用标记、时序、方向或设备密码；iPhone 还可选择照片封面。修改密码后，其他手机和手表需要更新本地保存的密码。
5. 在门锁所在位置，进入设置选择“使用当前位置”，保存后用于首页推荐。定位为可选权限，拒绝后仍可手动开门。

首页优先突出附近蓝牙信号较强的已保存门锁，其次是距保存位置约 150 米以内的门锁，再回退到常用、最近使用和其他已保存门锁。扫描结束后更新推荐，蓝牙附近记录约 30 秒后失效。信号强度和位置仅用于推荐，不代表门锁可达，也不会自动开门。定位只在使用 App 时按需获取，位置保存在本机；封面照片压缩保存且不保留原始照片元数据。

iPhone 开门时会启动实时活动，在锁屏和支持的灵动岛上显示进度，点按可返回对应门锁。系统关闭实时活动时，App 内开门仍正常工作。切换 App 或锁屏后，已主动发起的开门通过后台蓝牙继续短时等待回执；后台时间耗尽或状态过期时显示待确认，不会自动重试。扫描和定位在后台停止。实时活动的“设备已确认”仅表示收到指令回执，不是门磁检测结果。

两端使用 CoreBluetooth 提供的本地设备 UUID，而不是 MAC 地址。密码存储在各自设备的 Keychain，门禁名称及设置存储在本地 UserDefaults。App 不需要云服务。

## 协议与验证

`Shared/YiLaProtocol.swift` 负责密码派生、AES-ECB 零填充命令与响应解析；`Shared/BluetoothController.swift` 负责扫描、连接、通知订阅、发送、超时与取消。界面和存储由 `Shared/DoorViews.swift`、`DoorStore.swift`、`CredentialStore.swift` 共享，两端入口分别位于 `App/` 和 `WatchApp/`。

协议沿用设备要求的 MD5 密码派生和固定 AES 密钥，不代表现代安全协议。默认时序采用参考源码的 650 / 2000 / 650 毫秒；各项范围为 0 到 10000 毫秒。完整命令要求设备协商的单次写入长度足够；不对未知设备自行假设分包方式。

单元测试使用固定时间戳和独立加密向量验证协议兼容性。模拟器可检查界面与编译，但无法证明真实门禁兼容性。真机验收需要检查：发现目标门禁、正确密码开门、错误密码拒绝、断开 / 超时 / 取消，以及修改密码后重新开门。收到电量通知不等于开门成功；响应丢失时操作结果可能未知，不会自动重试。

## 许可

AGPL-3.0，详见 [LICENSE](LICENSE) 和 [NOTICE](NOTICE)。参考源码版本记录在 NOTICE 中。本项目与易拉及其制造商无关联。
