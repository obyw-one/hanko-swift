// Ed25519Tests.swift
// Ed25519 sign / verify round-trip + cross-language parity from Go seed.

import Foundation
import Testing
@testable import HankoCrypto

@Suite("HankoEd25519")
struct Ed25519Tests {
    @Test func generateKeyPairProducesUsableKeys() throws {
        let (pub, priv) = HankoEd25519.generateKeyPair()
        #expect(pub.count == 32)
        #expect(priv.count == 32)

        let message = Data("hanko/v0.1 round-trip".utf8)
        let signature = try HankoEd25519.sign(message, privateKey: priv)
        #expect(signature.count == 64)
        try HankoEd25519.verify(signature: signature, message: message, publicKey: pub)
    }

    @Test func keyPairFromDeterministicSeedMatchesGo() throws {
        // Critical parity test: seed 0x01..0x20 must yield the same public
        // key bytes as Go's ed25519.NewKeyFromSeed. Expected value comes
        // from the Go-generated fixture, not from this implementation.
        let vectors = try SignVerifyVector.load()
        #expect(!vectors.isEmpty)
        for v in vectors {
            let seed = try #require(Data(hexString: v.seedHex))
            let (pub, priv) = try HankoEd25519.keyPair(fromSeed: seed)
            #expect(pub.base64EncodedString() == v.publicKeyB64, "\(v.id): pubkey parity")
            #expect(priv == seed)
        }
    }

    @Test func verifyAcceptsValidSignature() throws {
        let (pub, priv) = HankoEd25519.generateKeyPair()
        let message = Data("valid message".utf8)
        let signature = try HankoEd25519.sign(message, privateKey: priv)
        try HankoEd25519.verify(signature: signature, message: message, publicKey: pub)
    }

    @Test func verifyRejectsTamperedMessage() throws {
        let (pub, priv) = HankoEd25519.generateKeyPair()
        let message = Data("original message".utf8)
        let signature = try HankoEd25519.sign(message, privateKey: priv)

        var tampered = message
        tampered[0] ^= 0x01
        #expect(throws: HankoEd25519.Error.signatureInvalid) {
            try HankoEd25519.verify(signature: signature, message: tampered, publicKey: pub)
        }
    }

    @Test func verifyRejectsWrongPublicKey() throws {
        let (_, priv) = HankoEd25519.generateKeyPair()
        let (otherPub, _) = HankoEd25519.generateKeyPair()
        let message = Data("message".utf8)
        let signature = try HankoEd25519.sign(message, privateKey: priv)
        #expect(throws: HankoEd25519.Error.signatureInvalid) {
            try HankoEd25519.verify(signature: signature, message: message, publicKey: otherPub)
        }
    }
}
