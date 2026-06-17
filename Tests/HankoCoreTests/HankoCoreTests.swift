// HankoCoreTests.swift
// Smoke tests for HankoCore wire types Codable behavior.

import Testing
import Foundation
@testable import HankoCore

@Suite("HankoCore wire types — Codable round-trip")
struct HankoCoreTests {

    @Test func sigilRoundTrip() throws {
        // TODO(W3.1): Encode + decode a HankoSigil, assert equality.
        // Use JSONEncoder.OutputFormatting = [] (no whitespace) to mimic
        // the Go wire format closely (though strictly only canonical JSON
        // matters for signed bodies).
    }

    @Test func capabilityTokenRoundTrip() throws {
        // TODO(W3.1): Same for HankoCapabilityToken.
    }

    @Test func revocationEntryRoundTrip() throws {
        // TODO(W3.1): Same for HankoRevocationEntry.
    }

    @Test func attestationEnvelopeRoundTrip() throws {
        // TODO(W3.1): Same for HankoAttestationEnvelope.
    }

    @Test func unsignedBodyStripsSignature() throws {
        // TODO(W3.1): Assert envelope.unsignedBody().signature.isEmpty.
    }
}
