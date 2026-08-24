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

import Foundation
import Testing
@testable import HankoBroker
@testable import HankoCore
@testable import HankoCrypto

/// One entry of `Fixtures/sign-verify.json` — file-scoped to keep type
/// nesting within the fleet lint limit.
private struct SignVerifyVector: Decodable {
    let id: String
    let description: String
    let seedHex: String
    let publicKeyB64: String
    let canonicalBody: String
    let signatureB64: String

    enum CodingKeys: String, CodingKey {
        case id, description
        case seedHex = "seed_hex"
        case publicKeyB64 = "public_key_b64"
        case canonicalBody = "canonical_body"
        case signatureB64 = "signature_b64"
    }
}

@Suite("Cross-language parity with Go")
struct ParityTests {
    private func hexData(_ hex: String) -> Data? {
        let chars = Array(hex)
        guard chars.count % 2 == 0 else { return nil }
        var bytes: [UInt8] = []
        for i in stride(from: 0, to: chars.count, by: 2) {
            guard let b = UInt8(String(chars[i...i + 1]), radix: 16) else { return nil }
            bytes.append(b)
        }
        return Data(bytes)
    }

    @Test func signVerifyVectorsLoadAndVerify() throws {
        let url = try #require(
            Bundle.module.url(forResource: "sign-verify", withExtension: "json"),
            "sign-verify.json fixture missing from bundle"
        )
        let vectors = try JSONDecoder().decode([SignVerifyVector].self, from: Data(contentsOf: url))
        #expect(!vectors.isEmpty)

        for v in vectors {
            // a. Seed → pubkey parity with Go's ed25519.NewKeyFromSeed.
            let seed = try #require(hexData(v.seedHex), "\(v.id): bad seed hex")
            let (pub, _) = try HankoEd25519.keyPair(fromSeed: seed)
            #expect(pub.base64EncodedString() == v.publicKeyB64, "\(v.id): pubkey parity")

            // b + c. Go-produced signature over the Go-produced canonical
            // body must verify with the derived key.
            let body = Data(v.canonicalBody.utf8)
            let signature = try #require(Data(base64Encoded: v.signatureB64), "\(v.id): bad sig b64")
            try HankoEd25519.verify(signature: signature, message: body, publicKey: pub)
        }
    }

    @Test func canonicalJSONVectorsMatchByteForByte() throws {
        let url = try #require(
            Bundle.module.url(forResource: "canonical-json", withExtension: "json"),
            "canonical-json.json fixture missing from bundle"
        )
        let raw = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        let entries = try #require(raw as? [[String: Any]])
        #expect(!entries.isEmpty)

        for e in entries {
            let id = try #require(e["id"] as? String)
            let input = try #require(e["input"])
            let expected = try #require(e["expected_canonical"] as? String)
            let got = try #require(String(bytes: HankoCanonicalJSON.encode(input), encoding: .utf8))
            #expect(got == expected, "\(id): byte parity with Go")
        }
    }
}
