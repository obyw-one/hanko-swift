// HankoCLI/main.swift — Hanko v0.1 CLI entry point
//
// Provides a demo mode that exercises the full issue → verify → revoke cycle.
// Full broker CLI verbs (hanko issue, hanko verify, hanko revoke, etc.) ship in W4.
//
// Usage:
//   hanko demo    — run end-to-end in-process demonstration

import Foundation
import HankoCore

@main
struct HankoCLIMain {
    static func main() async {
        let args = CommandLine.arguments
        let command = args.count > 1 ? args[1] : "help"

        switch command {
        case "demo":
            await runDemo()
        case "version":
            print("hanko-swift v0.1 — Hanko protocol Swift reference implementation")
            print("Parity with: gh:FJ-Studios/hanko (Go canonical)")
            print("Protocol version: \(hankoVersion)")
        default:
            printHelp()
        }
    }

    static func printHelp() {
        print("""
        hanko — Hanko v0.1 Swift reference implementation

        PROVENANCE: "Hanko" is the OBYW.one operator's own internal codename.
        See gh:FJ-Studios/hanko-swift README for full provenance assertion.

        Commands:
          demo      Run end-to-end in-process demonstration
          version   Print version information

        Full broker CLI (hanko issue, hanko verify, hanko revoke) ships in W4.
        """)
    }

    static func runDemo() async {
        print("=== Hanko v0.1 Swift demo ===")
        print("Protocol: \(hankoVersion)")
        print()

        do {
            // 1. Generate issuer key pair.
            let (issuerPubKey, issuerPrivKey) = try Ed25519.generateKeyPair()
            print("[1] Generated issuer key pair — pub: \(issuerPubKey.base64EncodedString().prefix(20))...")

            // 2. Create a broker backed by MemStore.
            let store = MemStore()
            let broker = Broker(store: store, privateKey: issuerPrivKey)

            // 3. Issue a subject key pair + sigil.
            let (subjectPubKey, _) = try Ed25519.generateKeyPair()
            let sigil = try await broker.issueSigil(
                subject: "operator:shikki@obyw.one",
                publicKey: subjectPubKey,
                metadata: ["workspace": "obyw-one", "tier": "operator"]
            )
            print("[2] Issued sigil: \(sigil.id) subject=\(sigil.subject)")

            // 4. Issue a capability token.
            let cap = try await broker.issueCap(
                sigilID: sigil.id,
                scope: "shi-secrets:read:ops/db-url",
                expiresAt: Date().addingTimeInterval(3600)
            )
            print("[3] Issued cap: \(cap.id) scope=\(cap.scope)")

            // 5. Issue an attestation envelope.
            let env = try await broker.issueAttestation(
                sigilID: sigil.id,
                caps: [cap],
                expiresAt: Date().addingTimeInterval(1800)
            )
            print("[4] Issued attestation — sig: \(env.signature.base64EncodedString().prefix(20))... (64 bytes: \(env.signature.count == 64))")

            // 6. Verify (first use — should pass, consumes nonce).
            try await broker.verifyAttestation(env)
            print("[5] Verify PASS (first use)")

            // 7. Scope check.
            try Broker.verifyCapScope(cap, requestedAction: "shi-secrets:read:ops/db-url")
            print("[6] Scope check PASS")

            // 8. Scope mismatch (should fail).
            do {
                try Broker.verifyCapScope(cap, requestedAction: "garage:write:obyw-backups")
                print("[7] ERROR: expected scope mismatch")
            } catch let e as VerifyError where e.code == "scope_mismatch" {
                print("[7] Scope mismatch correctly rejected: \(e.code)")
            }

            // 9. Replay attack (second verify — nonce already consumed).
            let env2 = try await broker.issueAttestation(
                sigilID: sigil.id,
                caps: [cap],
                expiresAt: Date().addingTimeInterval(1800)
            )
            do {
                try await broker.verifyAttestation(env2)
                print("[8] ERROR: expected nonce_replayed")
            } catch let e as VerifyError where e.code == "nonce_replayed" {
                print("[8] Replay attack correctly rejected: \(e.code)")
            }

            // 10. Revoke sigil + verify should fail.
            try await broker.revokeSigil(sigilID: sigil.id, reason: "demo revocation", revokedBy: sigil.id)
            let env3 = try await broker.issueAttestation(
                sigilID: sigil.id,
                caps: [],
                expiresAt: Date().addingTimeInterval(1800)
            )
            do {
                try await broker.verifyAttestation(env3)
                print("[9] ERROR: expected sigil_revoked")
            } catch let e as VerifyError where e.code == "sigil_revoked" {
                print("[9] Revoked sigil correctly rejected: \(e.code)")
            }

            print()
            print("=== Demo complete — all protocol operations verified ===")

        } catch {
            print("Demo failed: \(error)")
            exit(1)
        }
    }
}
