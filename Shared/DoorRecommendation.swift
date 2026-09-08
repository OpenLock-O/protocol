import Foundation

enum DoorRecommendations {
    static func recommend(doors: [Door], nearby: [NearbyDoor], location: DoorLocation?) -> DoorRecommendation? {
        var strongest: (door: Door, rssi: Int)?
        for door in doors {
            guard let signal = nearby.filter({ $0.id == door.id && (-75 ... -1).contains($0.rssi) })
                .map(\.rssi).max() else { continue }
            if strongest.map({ signal > $0.rssi }) ?? true {
                strongest = (door, signal)
            }
        }
        if let strongest {
            return DoorRecommendation(doorID: strongest.door.id, reason: "附近蓝牙信号较强")
        }

        if let location, isValid(location) {
            var closest: (door: Door, meters: Double)?
            for door in doors {
                guard let saved = door.location, isValid(saved) else { continue }
                let meters = distance(from: location, to: saved)
                guard meters <= 150 else { continue }
                if closest.map({ meters < $0.meters }) ?? true {
                    closest = (door, meters)
                }
            }
            if let closest {
                return DoorRecommendation(doorID: closest.door.id, reason: "靠近已保存的位置")
            }
        }

        if let favorite = doors.first(where: { $0.isFavorite == true }) {
            return DoorRecommendation(doorID: favorite.id, reason: "常用门锁")
        }
        var recent: Door?
        for door in doors {
            guard let opened = door.lastOpenedAt, opened.timeIntervalSinceReferenceDate.isFinite else { continue }
            if recent?.lastOpenedAt.map({ opened > $0 }) ?? true { recent = door }
        }
        if let recent {
            return DoorRecommendation(doorID: recent.id, reason: "最近使用")
        }
        return doors.first.map { DoorRecommendation(doorID: $0.id, reason: "已保存的门锁") }
    }

    private static func isValid(_ location: DoorLocation) -> Bool {
        location.latitude.isFinite && location.longitude.isFinite &&
        (-90...90).contains(location.latitude) && (-180...180).contains(location.longitude)
    }

    private static func distance(from: DoorLocation, to: DoorLocation) -> Double {
        let radians = Double.pi / 180
        let latitudeDelta = (to.latitude - from.latitude) * radians
        let longitudeDelta = (to.longitude - from.longitude) * radians
        let halfChord = pow(sin(latitudeDelta / 2), 2) +
            cos(from.latitude * radians) * cos(to.latitude * radians) * pow(sin(longitudeDelta / 2), 2)
        return 6_371_000 * 2 * asin(sqrt(min(1, max(0, halfChord))))
    }
}
