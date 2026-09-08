import Combine
import CoreLocation
import Foundation

@MainActor
final class DoorLocationManager: NSObject, ObservableObject {
    @Published private(set) var currentLocation: DoorLocation?
    @Published private(set) var isLocating = false
    @Published private(set) var message: String?

    private enum RequestState {
        case idle, awaitingPermission, locating
    }

    private var manager: CLLocationManager?
    private var state: RequestState = .idle
    private var timeoutTask: Task<Void, Never>?
    private var expiryTask: Task<Void, Never>?
    private var requestID = UUID()

    func requestLocation() {
        beginRequest(allowPermissionPrompt: true)
    }

    func refreshIfAuthorized() {
        beginRequest(allowPermissionPrompt: false)
    }

    func stop() {
        resetRequest()
        expiryTask?.cancel()
        expiryTask = nil
        currentLocation = nil
        message = nil
    }

    private func beginRequest(allowPermissionPrompt: Bool) {
        stop()
        let manager = CLLocationManager()
        self.manager = manager
        manager.desiredAccuracy = kCLLocationAccuracyNearestTenMeters
        manager.delegate = self

        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            startLocationRequest(manager)
        case .notDetermined where allowPermissionPrompt:
            state = .awaitingPermission
            isLocating = true
            scheduleTimeout(seconds: 60)
            manager.requestWhenInUseAuthorization()
        case .notDetermined:
            break
        case .denied, .restricted:
            finish(message: "定位权限未开启，可在系统设置中允许访问位置。")
        @unknown default:
            finish(message: "暂时无法使用定位。")
        }
    }

    private func startLocationRequest(_ manager: CLLocationManager) {
        state = .locating
        isLocating = true
        scheduleTimeout(seconds: 20)
        manager.requestLocation()
    }

    private func scheduleTimeout(seconds: UInt64) {
        timeoutTask?.cancel()
        let id = requestID
        timeoutTask = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: seconds * 1_000_000_000)
            } catch {
                return
            }
            guard let self, self.requestID == id else { return }
            self.finish(message: "暂时无法获取位置，请稍后重试。")
        }
    }

    private func finish(message: String?) {
        timeoutTask?.cancel()
        timeoutTask = nil
        manager?.stopUpdatingLocation()
        state = .idle
        isLocating = false
        self.message = message
    }

    private func resetRequest() {
        timeoutTask?.cancel()
        timeoutTask = nil
        manager?.stopUpdatingLocation()
        manager?.delegate = nil
        manager = nil
        requestID = UUID()
        state = .idle
        isLocating = false
    }

    private func accept(_ location: CLLocation) {
        currentLocation = DoorLocation(
            latitude: location.coordinate.latitude,
            longitude: location.coordinate.longitude
        )
        finish(message: nil)
        expiryTask?.cancel()
        let remainingLifetime = max(0, 60 - Date().timeIntervalSince(location.timestamp))
        let id = requestID
        expiryTask = Task { [weak self] in
            do {
                try await Task.sleep(nanoseconds: UInt64(remainingLifetime * 1_000_000_000))
            } catch {
                return
            }
            guard let self, self.requestID == id else { return }
            self.currentLocation = nil
            self.expiryTask = nil
        }
    }

    deinit {
        timeoutTask?.cancel()
        expiryTask?.cancel()
    }
}

// The manager is created on the main actor, so Core Location delivers callbacks on the main run loop.
extension DoorLocationManager: @preconcurrency CLLocationManagerDelegate {
    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        guard manager === self.manager else { return }
        switch manager.authorizationStatus {
        case .authorizedAlways, .authorizedWhenInUse:
            if state == .awaitingPermission {
                startLocationRequest(manager)
            }
        case .denied, .restricted:
            expiryTask?.cancel()
            expiryTask = nil
            currentLocation = nil
            finish(message: "定位权限未开启，可在系统设置中允许访问位置。")
        case .notDetermined:
            expiryTask?.cancel()
            expiryTask = nil
            currentLocation = nil
            if state != .awaitingPermission {
                finish(message: nil)
            }
        @unknown default:
            stop()
            message = "暂时无法使用定位。"
        }
    }

    func locationManager(_ manager: CLLocationManager, didUpdateLocations locations: [CLLocation]) {
        guard manager === self.manager, state == .locating else { return }
        guard manager.authorizationStatus == .authorizedWhenInUse || manager.authorizationStatus == .authorizedAlways else {
            locationManagerDidChangeAuthorization(manager)
            return
        }
        let now = Date()
        let location = locations.filter { location in
            let age = now.timeIntervalSince(location.timestamp)
            let coordinate = location.coordinate
            return age.isFinite && age >= 0 && age <= 60
                && location.horizontalAccuracy.isFinite
                && location.horizontalAccuracy >= 0 && location.horizontalAccuracy <= 100
                && coordinate.latitude.isFinite && coordinate.longitude.isFinite
                && CLLocationCoordinate2DIsValid(coordinate)
        }.max { $0.timestamp < $1.timestamp }

        guard let location else {
            finish(message: "位置精度不足，请移至信号较好的地方后重试。")
            return
        }
        accept(location)
    }

    func locationManager(_ manager: CLLocationManager, didFailWithError error: Error) {
        guard manager === self.manager, state != .idle else { return }
        if (error as? CLError)?.code == .denied {
            expiryTask?.cancel()
            expiryTask = nil
            currentLocation = nil
            finish(message: "定位不可用，请检查系统定位服务与位置权限。")
        } else {
            finish(message: "暂时无法获取位置，请稍后重试。")
        }
    }
}
