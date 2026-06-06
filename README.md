# hanko-swift — Hanko protocol Swift reference implementation

[![swift test](https://github.com/FJ-Studios/hanko-swift/actions/workflows/test.yml/badge.svg)](https://github.com/FJ-Studios/hanko-swift/actions/workflows/test.yml)

## Provenance — NOT teamhanko/hanko

> **ASSERT PROVENANCE (spec §1.1):** The name "Hanko" in this codebase is the
> operator's own pre-existing internal codename, conceived independently.
> The German startup teamhanko/hanko (a passkey/passwordless auth project,
> AGPL-3, first commit 2022) is a completely unrelated third-party project.
> There is zero code, dependency, or design inheritance between this codebase
> and teamhanko/hanko. The phonetic choice (Mo-to / Han-ko) was
> operator-intentional; the collision is irrelevant because Hanko is not
> customer-facing. Hanko is the OBYW.one internal identity protocol codename.

## What is Hanko?

Hanko is the internal identity and authorization primitive for the OBYW.one /
Moto platform stack. It issues, verifies, and revokes cryptographically-attested
identity sigils and capability tokens. Moto customers never see "Hanko" — they
see Moto login and access grants. Hanko is the plumbing.

This repository is the **Swift reference implementation**, targeting:
- `packages/ShikkiCore/Sources/ShikkiCore/Hanko/` (Shikki kernel identity)
- `packages/Kotoba/` (audio pipeline identity)
- Future iOS / macOS client surfaces

**Go canonical implementation:** `gh:FJ-Studios/hanko` (commit b91dd0fc, 17/17 tests).
Any protocol ambiguity is resolved by running the Go `hanko-broker` binary.
The Swift implementation is a follower, not a co-equal.

## Protocol primitives (spec §2.1)

| Primitive | Description |
|---|---|
| `Sigil` | Stable cryptographic identity for an operator, agent, or service |
| `CapabilityToken` | Scoped, time-bounded authorization grant tied to a Sigil |
| `AttestationEnvelope` | Signed wrapper binding Sigil + caps + issuer + expiry |
| `RevocationList` | Append-only log of revoked Sigils and capability tokens |

**Wire format:** canonical JSON (RFC 8785 key ordering, RFC3339 timestamps,
base64-standard encoding for binary fields). Protobuf deferred to v0.2.

**Crypto:** Ed25519 via `CryptoKit` (`Curve25519.Signing`). No third-party
crypto dependencies. No CGO. Works on Apple platforms and Linux (Swift 6.0+).

## Requirements

- Swift 6.0+
- macOS 14+ or Linux with Swift 6.0 toolchain
- No external dependencies — CryptoKit + Foundation only

## Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/FJ-Studios/hanko-swift.git", from: "0.1.0"),
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "HankoCore", package: "hanko-swift")
        ]
    )
]
```

## Usage

### Issue a Sigil

```swift
import HankoCore

// Generate issuer key pair
let (issuerPub, issuerPriv) = try Ed25519.generateKeyPair()

// Create a broker backed by MemStore
let store = MemStore()
let broker = Broker(store: store, privateKey: issuerPriv)

// Issue a subject key pair and register a sigil
let (subjectPub, _) = try Ed25519.generateKeyPair()
let sigil = try await broker.issueSigil(
    subject: "operator:shikki@obyw.one",
    publicKey: subjectPub,
    metadata: ["workspace": "obyw-one"]
)
```

### Issue a CapabilityToken

```swift
let cap = try await broker.issueCap(
    sigilID: sigil.id,
    scope: "shi-secrets:read:ops/db-url",
    expiresAt: Date().addingTimeInterval(3600)
)
```

### Issue and verify an AttestationEnvelope

```swift
let env = try await broker.issueAttestation(
    sigilID: sigil.id,
    caps: [cap],
    expiresAt: Date().addingTimeInterval(1800)
)

do {
    try await broker.verifyAttestation(env)
    // Valid — nonce consumed
} catch let e as VerifyError {
    switch e.code {
    case "signature_invalid": // tampered
    case "sigil_revoked":     // revoked
    case "capability_expired": // expired
    case "nonce_replayed":    // replay attack
    default: break
    }
}
```

### Scope check

```swift
do {
    try Broker.verifyCapScope(cap, requestedAction: "shi-secrets:read:ops/db-url")
} catch let e as VerifyError where e.code == "scope_mismatch" {
    // granted scope doesn't cover requested action
}
```

### Revoke a Sigil

```swift
try await broker.revokeSigil(
    sigilID: sigil.id,
    reason: "key compromise",
    revokedBy: issuerSigilID
)
```

## Test

```bash
swift test
# or with parallelism
swift test --parallel
```

All 17 tests must pass:
- 4 broker happy-path tests (BrokerTests)
- 5 crypto tests (CryptoTests)
- 5 protocol round-trip tests (ProtocolRoundTripTests)
- 5 negative fixtures from spec §7 (NegativeFixtureTests)
- 3 cross-language parity tests (CrossLangParityTests)

## Repository layout

```
hanko-swift/
  Sources/
    HankoCore/
      Protocol/Types.swift       — Sigil, CapabilityToken, AttestationEnvelope, RevocationList
      Crypto/CanonicalJSON.swift — RFC 8785-compatible canonical JSON serialiser
      Crypto/Ed25519.swift       — Ed25519 sign/verify + nonce generation (CryptoKit)
      Store/MemStore.swift       — Thread-safe in-memory store (actor)
      Broker/Broker.swift        — Issue / verify / revoke logic (actor)
    HankoCLI/
      main.swift                 — Demo CLI (full broker CLI ships in W4)
  Tests/
    HankoCoreTests/
      BrokerTests.swift          — 4 broker happy-path tests
      CryptoTests.swift          — 5 crypto tests
      ProtocolRoundTripTests.swift — 5 JSON round-trip tests
      NegativeFixtureTests.swift — 5 negative fixture tests (spec §7)
      CrossLangParityTests.swift — Cross-language wire parity tests
      TestVectors/
        negative-fixtures.json   — Vendored from gh:FJ-Studios/hanko/docs/
  docs/
    test-vectors.md              — Cross-language verification guide
  .github/workflows/test.yml    — CI (macOS 15 + Linux Swift 6.0)
```

## Wave plan

| Wave | Deliverable | Status |
|---|---|---|
| W1 | Protocol spec + JSON wire format | done (spec file) |
| W2 | Go reference impl (`gh:FJ-Studios/hanko`) | done — 17/17 tests |
| W3 | **Swift implementation (this repo)** | **done — 17/17 tests** |
| W4 | Postgres schema + full broker CLI | planned |
| W5 | e2e tests + negative fixtures (live Postgres) | planned |

## License

AGPL-3.0 — see [LICENSE](LICENSE).
