// CanonicalJSONTests.swift
// Canonical JSON behavior (Go-parity flavor) + parity vectors from Go.

import Foundation
import Testing
@testable import HankoCore
@testable import HankoCrypto

@Suite("HankoCanonicalJSON — Go-parity canonical form")
struct CanonicalJSONTests {
    private func canonical(_ value: Any) throws -> String {
        try #require(String(bytes: HankoCanonicalJSON.encode(value), encoding: .utf8))
    }

    // MARK: Basics

    @Test func keysAreSortedLexicographically() throws {
        #expect(try canonical(["b": 1, "a": 2]) == #"{"a":2,"b":1}"#)
    }

    @Test func nestedObjectsAreSortedRecursively() throws {
        #expect(try canonical(["z": ["b": 1, "a": 2]]) == #"{"z":{"a":2,"b":1}}"#)
    }

    @Test func noWhitespaceBetweenTokens() throws {
        #expect(try canonical(["a": 1]) == #"{"a":1}"#)
    }

    @Test func arraysPreserveOrder() throws {
        #expect(try canonical(["items": [3, 1, 2]]) == #"{"items":[3,1,2]}"#)
    }

    @Test func controlCharactersAreEscaped() throws {
        #expect(try canonical(["c": "\u{01}"]) == "{\"c\":\"\\u0001\"}")
    }

    @Test func unicodePassesThrough() throws {
        #expect(try canonical(["msg": "café"]) == #"{"msg":"café"}"#)
    }

    @Test func datesUseRFC3339Z() throws {
        var comps = DateComponents()
        comps.year = 2026
        comps.month = 6
        comps.day = 6
        comps.hour = 12
        comps.minute = 0
        comps.second = 0
        comps.timeZone = TimeZone(identifier: "UTC")
        let date = try #require(Calendar(identifier: .gregorian).date(from: comps))
        #expect(try canonical(["at": date]) == #"{"at":"2026-06-06T12:00:00Z"}"#)
    }

    @Test func dataEncodesAsBase64Std() throws {
        let nonce = Data([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        #expect(try canonical(["nonce": nonce]) == #"{"nonce":"AQIDBAUGBwgJCgsMDQ4PEA=="}"#)
    }

    @Test func encodableEnvelopeOmitsEmptySignature() throws {
        // Matches Go: the signed body has no `signature` key (spec §2.1).
        let envelope = HankoAttestationEnvelope(
            sigilID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            caps: [],
            issuer: "hanko-broker@obyw.one",
            issuedAt: Date(timeIntervalSince1970: 1_780_747_200), // 2026-06-06T12:00:00Z
            expiresAt: Date(timeIntervalSince1970: 1_780_750_800) // 2026-06-06T13:00:00Z
        )
        let body = try #require(String(bytes: HankoCanonicalJSON.encode(envelope.unsignedBody()), encoding: .utf8))
        #expect(!body.contains("signature"))
        #expect(body.hasPrefix(#"{"caps":[]"#))
    }

    // MARK: Parity vectors

    @Test func parityWithGoCanonicalJSON() throws {
        let vectors = try CanonicalVector.load()
        #expect(!vectors.isEmpty)
        for v in vectors {
            #expect(try canonical(v.input) == v.expected, "\(v.id): byte parity with Go")
        }
    }
}
