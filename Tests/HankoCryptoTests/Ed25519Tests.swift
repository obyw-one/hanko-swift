// Ed25519Tests.swift
// Ed25519 sign / verify round-trip + cross-language parity from Go seed.

import Testing
import Foundation
@testable import HankoCrypto

@Suite("HankoEd25519")
struct Ed25519Tests {

    @Test func generateKeyPairProducesUsableKeys() throws {
        // TODO(W3.1): generate, sign, verify round-trip.
    }

    @Test func keyPairFromDeterministicSeedMatchesGo() throws {
        // TODO(W3.1): Critical parity test.
        // Seed = bytes 0x01..0x20 (matches Go's deterministicSeed).
        // Expected pubkey base64-std MUST match Go's TestGenerateVectors
        // output. Read from Fixtures/sign-verify.json (SV-1 PublicKeyB64).
    }

    @Test func verifyAcceptsValidSignature() throws {
        // TODO(W3.1).
    }

    @Test func verifyRejectsTamperedMessage() throws {
        // TODO(W3.1): Flip 1 bit in the message, expect Error.signatureInvalid.
    }

    @Test func verifyRejectsWrongPublicKey() throws {
        // TODO(W3.1): Use a different keypair's pubkey, expect failure.
    }
}
