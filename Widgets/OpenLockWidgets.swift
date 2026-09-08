import ActivityKit
import SwiftUI
import WidgetKit

@main
struct OpenLockWidgets: WidgetBundle {
    var body: some Widget {
        UnlockLiveActivity()
    }
}

struct UnlockLiveActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: UnlockActivityAttributes.self) { context in
            UnlockActivityContent(context: context)
                .activityBackgroundTint(Color(uiColor: .systemBackground))
                .activitySystemActionForegroundColor(.primary)
                .widgetURL(context.doorURL)
        } dynamicIsland: { context in
            let phase = context.displayPhase

            return DynamicIsland {
                DynamicIslandExpandedRegion(.leading) {
                    Image(systemName: context.attributes.iconName)
                        .font(.title2)
                        .foregroundStyle(phase.tint)
                        .frame(width: 36, height: 36)
                        .accessibilityHidden(true)
                }
                DynamicIslandExpandedRegion(.trailing) {
                    ActivityStatusSymbol(phase: phase)
                        .frame(width: 36, height: 36)
                }
                DynamicIslandExpandedRegion(.bottom) {
                    VStack(alignment: .leading, spacing: 5) {
                        Text(context.attributes.doorName)
                            .font(.headline)
                            .lineLimit(1)
                            .truncationMode(.tail)
                            .privacySensitive()
                        Text(phase.label)
                            .font(.subheadline)
                            .foregroundStyle(phase.tint)
                            .lineLimit(2)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.bottom, 4)
                }
            } compactLeading: {
                Image(systemName: context.attributes.iconName)
                    .foregroundStyle(phase.tint)
                    .accessibilityLabel("OpenLock")
            } compactTrailing: {
                ActivityStatusSymbol(phase: phase)
                    .frame(width: 22, height: 22)
            } minimal: {
                ActivityStatusSymbol(phase: phase)
                    .frame(width: 22, height: 22)
            }
            .widgetURL(context.doorURL)
            .keylineTint(phase.tint)
        }
    }
}

private struct UnlockActivityContent: View {
    let context: ActivityViewContext<UnlockActivityAttributes>

    var body: some View {
        let phase = context.displayPhase

        HStack(spacing: 14) {
            Image(systemName: context.attributes.iconName)
                .font(.system(size: 28, weight: .medium))
                .foregroundStyle(phase.tint)
                .frame(width: 42, height: 48)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: 5) {
                Text(context.attributes.doorName)
                    .font(.headline)
                    .lineLimit(2)
                    .truncationMode(.tail)
                    .privacySensitive()
                Text(phase.label)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .frame(maxWidth: .infinity, alignment: .leading)

            ActivityStatusSymbol(phase: phase)
                .font(.title3)
                .frame(width: 28, height: 28)
                .accessibilityHidden(true)
        }
        .padding(18)
    }
}

private struct ActivityStatusSymbol: View {
    let phase: UnlockActivityAttributes.Phase

    var body: some View {
        Group {
            if phase.isRunning {
                ProgressView()
                    .tint(phase.tint)
            } else {
                Image(systemName: phase.symbol)
                    .foregroundStyle(phase.tint)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(phase.label)
    }
}

private extension ActivityViewContext where Attributes == UnlockActivityAttributes {
    var displayPhase: UnlockActivityAttributes.Phase {
        isStale && state.phase.isRunning ? .interrupted : state.phase
    }

    var doorURL: URL? {
        URL(string: "openlock://door/\(attributes.doorID.uuidString)")
    }
}

private extension UnlockActivityAttributes.Phase {
    var isRunning: Bool {
        switch self {
        case .connecting, .sending, .waiting: true
        case .confirmed, .failed, .interrupted: false
        }
    }

    var label: String {
        switch self {
        case .connecting: "连接门锁"
        case .sending: "发送指令"
        case .waiting: "等待设备确认"
        case .confirmed: "设备已确认"
        case .failed: "未能确认结果"
        case .interrupted: "状态待确认"
        }
    }

    var tint: Color {
        switch self {
        case .connecting, .sending, .waiting: .cyan
        case .confirmed: .green
        case .failed, .interrupted: .orange
        }
    }

    var symbol: String {
        switch self {
        case .connecting, .sending, .waiting: "wave.3.right"
        case .confirmed: "checkmark.circle.fill"
        case .failed: "exclamationmark.circle.fill"
        case .interrupted: "questionmark.circle.fill"
        }
    }
}
