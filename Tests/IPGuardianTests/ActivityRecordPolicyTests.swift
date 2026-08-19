import XCTest
@testable import IPGuardian

final class ActivityRecordPolicyTests: XCTestCase {
    func testRecoveryCreatesNewInfoWithoutReplacingError() {
        var records: [EventRecord] = []
        records = add("ERROR", "Country verification is temporarily unavailable.", to: records)
        let errorID = records[0].id

        records = add(
            "INFO",
            "The trusted connection was verified again; paused apps were resumed automatically.",
            to: records
        )

        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[0].level, "INFO")
        XCTAssertEqual(records[1].level, "ERROR")
        XCTAssertEqual(records[1].id, errorID)
    }

    func testSimilarErrorsAreMergedWithCounter() {
        var records: [EventRecord] = []
        records = add("ERROR", "Connection verification is temporarily unavailable.", to: records)
        records = add("ERROR", "Connection verification is temporarily unavailable.", to: records)

        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records[0].occurrenceCount, 2)
    }

    func testDifferentErrorsRemainSeparate() {
        var records: [EventRecord] = []
        records = add("ERROR", "Connection verification is temporarily unavailable.", to: records)
        records = add("ERROR", "Different connection countries were reported.", to: records)

        XCTAssertEqual(records.count, 2)
        XCTAssertNotEqual(records[0].message, records[1].message)
    }

    func testConsecutiveDuplicateInfoIsNotAdded() {
        var records: [EventRecord] = []
        records = add("INFO", "Protection turned off.", to: records)
        records = add("INFO", "Protection turned off.", to: records)

        XCTAssertEqual(records.count, 1)
    }

    func testFinalCriticalRecordDoesNotReplaceIncidentError() {
        var records: [EventRecord] = []
        records = add("ERROR", "Country verification is temporarily unavailable.", to: records)
        records = add(
            "CRITICAL",
            "Connection verification failed after 3 automatic retries; protected apps remain paused.",
            to: records
        )

        XCTAssertEqual(records.map(\.level), ["CRITICAL", "ERROR"])
    }

    func testActivityIsCappedAtTwoHundredRecords() {
        var records: [EventRecord] = []
        for index in 0..<240 {
            records = ActivityRecordPolicy.adding(
                level: "INFO",
                message: "Event \(index)",
                to: records,
                maximumRecords: 200
            )
        }

        XCTAssertEqual(records.count, 200)
        XCTAssertEqual(records.first?.message, "Event 239")
        XCTAssertEqual(records.last?.message, "Event 40")
    }

    private func add(
        _ level: String,
        _ message: String,
        to records: [EventRecord]
    ) -> [EventRecord] {
        ActivityRecordPolicy.adding(
            level: level,
            message: message,
            to: records,
            maximumRecords: 200
        )
    }
}
