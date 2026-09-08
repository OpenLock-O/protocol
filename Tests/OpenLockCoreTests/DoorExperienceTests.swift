import Foundation
import XCTest
@testable import OpenLockCore

final class DoorExperienceTests: XCTestCase {
    func testLegacySavedDoorDecodesWithoutNewMetadata() throws {
        let data = Data("""
        [{"id":"19EFD46E-E104-41DF-B923-2086552E038C","name":"Front door","openTime":650,"waitTime":2000,"closeTime":650,"reverse":false}]
        """.utf8)
        let door = try XCTUnwrap(JSONDecoder().decode([Door].self, from: data).first)
        XCTAssertEqual(door.name, "Front door")
        XCTAssertEqual(door.waitTime, 2000)
        XCTAssertNil(door.icon)
        XCTAssertNil(door.tint)
        XCTAssertNil(door.coverData)
        XCTAssertNil(door.location)
        XCTAssertNil(door.isFavorite)
        XCTAssertNil(door.lastOpenedAt)
    }

    func testPersonalizationSurvivesPersistenceRoundTrip() throws {
        let door = Door(id: UUID(), name: "Office", icon: .office, tint: .teal,
                        coverData: Data([1, 2, 3]), location: DoorLocation(latitude: 31.2, longitude: 121.5),
                        isFavorite: true, lastOpenedAt: Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(try JSONDecoder().decode(Door.self, from: JSONEncoder().encode(door)), door)
    }

    func testStrongSavedBluetoothSignalOutranksLocationAndFavorite() {
        let favorite = Door(id: UUID(), name: "Home", location: origin, isFavorite: true)
        let office = Door(id: UUID(), name: "Office")
        let result = DoorRecommendations.recommend(doors: [favorite, office], nearby: [signal(office, -48)], location: origin)
        XCTAssertEqual(result?.doorID, office.id)
    }

    func testUnknownInvalidAndWeakBluetoothSignalsCannotDisplaceFavorite() {
        let other = Door(id: UUID(), name: "Other")
        let favorite = Door(id: UUID(), name: "Favorite", isFavorite: true)
        for rssi in [127, 0, 1, -128, -90] {
            let observations = [signal(other, rssi), NearbyDoor(id: UUID(), name: "Unknown", rssi: -25, battery: nil)]
            XCTAssertEqual(DoorRecommendations.recommend(doors: [other, favorite], nearby: observations, location: nil)?.doorID,
                           favorite.id, "RSSI: \(rssi)")
        }
    }

    func testNearestSavedPositionWinsWithinWalkingRange() {
        let farther = Door(id: UUID(), name: "Farther", location: DoorLocation(latitude: 0.001, longitude: 0))
        let closer = Door(id: UUID(), name: "Closer", location: DoorLocation(latitude: 0.0005, longitude: 0))
        XCTAssertEqual(DoorRecommendations.recommend(doors: [farther, closer], nearby: [], location: origin)?.doorID, closer.id)
    }

    func testDistantAndInvalidPositionsFallBackToFavorite() {
        let distant = Door(id: UUID(), name: "Distant", location: DoorLocation(latitude: 1, longitude: 1))
        let invalid = Door(id: UUID(), name: "Invalid", location: DoorLocation(latitude: 91, longitude: 0))
        let favorite = Door(id: UUID(), name: "Favorite", isFavorite: true)
        for location in [origin, DoorLocation(latitude: .nan, longitude: 0), DoorLocation(latitude: 0, longitude: .infinity)] {
            XCTAssertEqual(DoorRecommendations.recommend(doors: [distant, invalid, favorite], nearby: [], location: location)?.doorID,
                           favorite.id)
        }
    }

    func testRecommendationTiesPreserveSavedOrderRegardlessOfScanOrder() {
        let date = Date(timeIntervalSince1970: 1_700_000_000)
        let first = Door(id: UUID(), name: "First", location: origin, lastOpenedAt: date)
        let second = Door(id: UUID(), name: "Second", location: origin, lastOpenedAt: date)
        let doors = [first, second]
        XCTAssertEqual(DoorRecommendations.recommend(doors: doors, nearby: [signal(second, -45), signal(first, -45)], location: nil)?.doorID,
                       first.id)
        XCTAssertEqual(DoorRecommendations.recommend(doors: doors, nearby: [], location: origin)?.doorID, first.id)
        XCTAssertEqual(DoorRecommendations.recommend(doors: doors, nearby: [], location: nil)?.doorID, first.id)
    }

    func testMostRecentlyOpenedDoorAndEmptyCollectionFallbacks() {
        let first = Door(id: UUID(), name: "First")
        let recent = Door(id: UUID(), name: "Recent", lastOpenedAt: Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(DoorRecommendations.recommend(doors: [first, recent], nearby: [], location: nil)?.doorID, recent.id)
        XCTAssertEqual(DoorRecommendations.recommend(doors: [first], nearby: [], location: nil)?.doorID, first.id)
        XCTAssertNil(DoorRecommendations.recommend(doors: [], nearby: [], location: nil))
    }

    private var origin: DoorLocation { DoorLocation(latitude: 0, longitude: 0) }

    private func signal(_ door: Door, _ rssi: Int) -> NearbyDoor {
        NearbyDoor(id: door.id, name: door.name, rssi: rssi, battery: nil)
    }
}
