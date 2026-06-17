// ParityTests.swift
// Cross-language parity with Go's gen_vectors_test.go output.
//
// Fixtures (copied from Go repo's docs/test-vectors/):
//   - Tests/HankoBrokerTests/Fixtures/sign-verify.json
//   - Tests/HankoBrokerTests/Fixtures/canonical-json.json
//
// HankoSwift MUST:
//   1. Derive the same Ed25519 pubkey from the SeedHex
//   2. Compute the same CanonicalBody from the structured input
//   3. Verify the SignatureB64 against CanonicalBody with the pubkey
//
// Any byte-level mismatch → parity broken → test fails.

import Testing
import Foundation
@testable import HankoBroker
@testable import HankoCore
@testable import HankoCrypto

@Suite("Cross-language parity with Go")
struct ParityTests {

    struct SignVerifyVector: Decodable {
        let id: String
        let description: String
        let seedHex: String
        let publicKeyB64: String
        let canonicalBody: String
        let signatureB64: String

        enum CodingKeys: String, CodingKey {
            case id, description
            case seedHex       = "seed_hex"
            case publicKeyB64  = "public_key_b64"
            case canonicalBody = "canonical_body"
            case signatureB64  = "signature_b64"
        }
    }

    @Test func signVerifyVectorsLoadAndVerify() throws {
        // TODO(W3.3):
        //   1. Bundle.module.url(forResource: "sign-verify", withExtension: "json")
        //   2. Decode [SignVerifyVector]
        //   3. For each vector:
        //      a. Derive (pub, priv) from seedHex → assert pub.base64 == publicKeyB64
        //      b. Decode canonicalBody as UTF-8 bytes
        //      c. Decode signatureB64 as bytes
        //      d. HankoEd25519.verify(signature, message: canonicalBody, publicKey: pub) → no throw
    }
}
