import ActivityKit
import Combine
import OSLog
import UIKit

@MainActor
final class UnlockActivityManager: ObservableObject {
    private typealias LockActivity = Activity<UnlockActivityAttributes>
    private let logger = Logger(subsystem: "dev.openlock.app", category: "LiveActivity")
    private var currentSessionID: UUID?
    private var displayed: (sessionID: UUID, activity: LockActivity)?
    private var pending: Task<Void, Never>?
    private var timeout: Task<Void, Never>?
    private var operationObservation: AnyCancellable?
    private var backgroundTask: (sessionID: UUID, identifier: UIBackgroundTaskIdentifier)?

    init() {
        let abandoned = LockActivity.activities
        enqueue {
            for activity in abandoned {
                await activity.end(
                    ActivityContent(state: .init(phase: .interrupted), staleDate: nil),
                    dismissalPolicy: .immediate
                )
            }
        }
    }

    func observe(_ states: AnyPublisher<OperationState, Never>) {
        operationObservation = states.removeDuplicates().sink { [weak self] state in
            self?.update(state)
        }
    }

    func start(door: Door) {
        timeout?.cancel()
        if let backgroundTask {
            endBackgroundTask(sessionID: backgroundTask.sessionID)
        }
        let sessionID = UUID()
        currentSessionID = sessionID
        let attributes = UnlockActivityAttributes(
            doorID: door.id,
            doorName: String(door.name.prefix(80)),
            iconName: door.icon?.rawValue ?? "door.left.hand.closed"
        )
        enqueue { [weak self] in
            guard let self else { return }
            if let previous = self.displayed {
                await previous.activity.end(
                    ActivityContent(state: .init(phase: .interrupted), staleDate: nil),
                    dismissalPolicy: .immediate
                )
                self.displayed = nil
            }
            guard self.currentSessionID == sessionID,
                  UIApplication.shared.applicationState == .active,
                  ActivityAuthorizationInfo().areActivitiesEnabled else { return }
            do {
                let activity = try LockActivity.request(
                    attributes: attributes,
                    content: ActivityContent(state: .init(phase: .connecting), staleDate: .now.addingTimeInterval(30)),
                    pushType: nil
                )
                self.displayed = (sessionID, activity)
            } catch {
                self.logger.notice("Live Activity could not start; in-app operation remains available.")
            }
        }
        timeout = Task { [weak self] in
            do { try await Task.sleep(for: .seconds(30)) } catch { return }
            guard let self, self.currentSessionID == sessionID else { return }
            self.finish(.interrupted, sessionID: sessionID)
        }
    }

    func update(_ state: OperationState) {
        guard let sessionID = currentSessionID else { return }
        let phase: UnlockActivityAttributes.Phase
        switch state {
        case .connecting: phase = .connecting
        case .sending: phase = .sending
        case .waiting: phase = .waiting
        case .succeeded:
            finish(.confirmed, sessionID: sessionID)
            return
        case .failed:
            finish(.failed, sessionID: sessionID)
            return
        case .idle:
            finish(.interrupted, sessionID: sessionID)
            return
        }
        enqueue { [weak self] in
            guard let displayed = self?.displayed, displayed.sessionID == sessionID else { return }
            await displayed.activity.update(
                ActivityContent(state: .init(phase: phase), staleDate: .now.addingTimeInterval(30))
            )
        }
    }

    func beginBackgroundGracePeriod() {
        guard let sessionID = currentSessionID, backgroundTask == nil else { return }
        let identifier = UIApplication.shared.beginBackgroundTask(withName: "Complete requested unlock") { [weak self] in
            Task { @MainActor [weak self] in
                guard let self else { return }
                self.finish(.interrupted, sessionID: sessionID)
                self.endBackgroundTask(sessionID: sessionID)
            }
        }
        guard identifier != .invalid else {
            finish(.interrupted, sessionID: sessionID)
            return
        }
        backgroundTask = (sessionID, identifier)
    }

    private func endBackgroundTask(sessionID: UUID) {
        guard let backgroundTask, backgroundTask.sessionID == sessionID else { return }
        self.backgroundTask = nil
        UIApplication.shared.endBackgroundTask(backgroundTask.identifier)
    }

    private func finish(_ phase: UnlockActivityAttributes.Phase, sessionID: UUID) {
        guard currentSessionID == sessionID else { return }
        currentSessionID = nil
        timeout?.cancel()
        timeout = nil
        enqueue { [weak self] in
            guard let self else { return }
            defer { self.endBackgroundTask(sessionID: sessionID) }
            guard let displayed = self.displayed, displayed.sessionID == sessionID else { return }
            await displayed.activity.end(
                ActivityContent(state: .init(phase: phase), staleDate: nil),
                dismissalPolicy: .after(.now.addingTimeInterval(phase == .confirmed ? 15 : 60))
            )
            self.displayed = nil
        }
    }

    // ActivityKit calls suspend; chain them so an older update cannot overwrite a later result.
    private func enqueue(_ action: @escaping @MainActor () async -> Void) {
        let previous = pending
        pending = Task {
            await previous?.value
            await action()
        }
    }
}
