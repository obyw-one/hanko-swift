// CanonicalJSONTests.swift
// RFC 8785 canonical JSON behavior + parity vectors from Go.

import Testing
import Foundation
@testable import HankoCrypto
@testable import HankoCore

@Suite("HankoCanonicalJSON — RFC 8785")
struct CanonicalJSONTests {

    // MARK: RFC 8785 basics

    @Test func keysAreSortedLexicographically() throws {
        // TODO(W3.1): { "b": 1, "a": 2 } → {"a":2,"b":1}
    }

    @Test func nestedObjectsAreSortedRecursively() throws {
        // TODO(W3.1): { "z": { "b": 1, "a": 2 } } → {"z":{"a":2,"b":1}}
    }

    @Test func noWhitespaceBetweenTokens() throws {
        // TODO(W3.1): { "a": 1 } → {"a":1}
    }

    @Test func controlCharactersAreEscaped() throws {
        // TODO(W3.1): "\u{01}" → "\\u0001"
    }

    @Test func unicodePassesThrough() throws {
        // TODO(W3.1): "café" → "café" (UTF-8 bytes, no escape)
    }

    @Test func datesUseRFC3339Z() throws {
        // TODO(W3.1): Date(2026-06-06 12:00:00 UTC) → "2026-06-06T12:00:00Z"
    }

    // MARK: Parity vectors

    @Test func parityWithGoCanonicalJSON() throws {
        // TODO(W3.1): Load canonical-json.json fixture (copied from Go's
        // docs/test-vectors/canonical-json.json) and assert byte-equality
        // for every (input, expected_canonical) pair.
        //
        // Fixture path (via Bundle.module):
        //   Tests/HankoCryptoTests/Fixtures/canonical-json.json
    }
}
