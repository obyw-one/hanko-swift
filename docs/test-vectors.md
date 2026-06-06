# Hanko v0.1 — Cross-Language Test Vectors

This document describes how to verify byte-level parity between the Swift
reference implementation (`gh:FJ-Studios/hanko-swift`) and the Go canonical
implementation (`gh:FJ-Studios/hanko`).

## Canonical JSON parity

The canonical JSON algorithm in both implementations follows the same rules:
1. Sort all object keys alphabetically (ascending Unicode code point order).
2. No optional whitespace.
3. Recursive: nested objects and arrays follow the same rules.

**Fixed test vector** (same in Go and Swift):

Input: `{"z": 1, "a": 2, "m": 3}` (in any insertion order)
Output: `{"a":2,"m":3,"z":1}`

Run in Go:
```bash
cd /path/to/hanko
go test ./crypto/ -run TestCanonicalJSONDeterminism -v
```

Run in Swift:
```bash
swift test --filter testCanonicalJSONDeterminism
```

Both must produce: `{"a":2,"m":3,"z":1}`

## Binary field encoding

Go `encoding/json` encodes `[]byte` as base64-standard (with padding).
Swift `JSONEncoder.dataEncodingStrategy = .base64` produces identical output.

**Fixed test vector** (nonce bytes 1..16):

Input bytes: `[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]`
Base64-standard output: `AQIDBAUGBwgJCgsMDQ4P`

## Timestamp encoding

Go `time.Time.UTC().Format(time.RFC3339)` produces `"2026-06-06T00:00:00Z"`.
Swift custom `dateEncodingStrategy` (RFC3339 UTC formatter) produces identical output.

**Fixed test vector**:

Unix timestamp: `1749168000` (2026-06-06T00:00:00Z)
RFC3339 output: `"2026-06-06T00:00:00Z"`

## Ed25519 signature parity

Ed25519 (RFC 8032) is deterministic given the same message and private key.
To verify byte-level signature parity:

1. Generate a fixed 32-byte private key seed (e.g., all zeros: `000...0`).
2. Derive the key pair in both Go and Swift.
3. Sign the same canonical JSON body.
4. Compare the 64-byte signature hex.

Note: Key *generation* (`crypto/rand`) is non-deterministic. Cross-language
signature equality can only be verified with a fixed key seed, which is not
done in the automated test suite (it would require exposing the raw seed).
The automated tests verify internal round-trip consistency; full cross-language
vector comparison is manual.

## Negative fixtures

All 5 negative fixtures from spec §7 are vendored in:
- Go: `docs/negative-fixtures.json` + `tests/negative/negative_test.go`
- Swift: `Tests/HankoCoreTests/TestVectors/negative-fixtures.json` + `Tests/HankoCoreTests/NegativeFixtureTests.swift`

Both fixture suites must produce `DENIED` outcomes for identical scenarios.
