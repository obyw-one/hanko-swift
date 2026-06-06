// Crypto/CanonicalJSON.swift — RFC 8785-compatible canonical JSON for Hanko signing
//
// Ported from Go's hanko/crypto package (gh:FJ-Studios/hanko, commit b91dd0fc).
// Produces byte-identical output to the Go CanonicalJSON function for the
// field types used by Hanko protocol types.
//
// Rules (matching Go marshalCanonical + wire-format.md):
//   1. All object keys sorted alphabetically (ascending Unicode code point order).
//   2. No optional whitespace.
//   3. Timestamps: RFC3339 UTC, e.g. "2026-06-06T12:00:00Z".
//   4. Binary fields (Data): base64-standard encoded (matching Go encoding/json []byte).
//   5. Nested objects and arrays follow the same rules recursively.

import Foundation

/// Errors thrown by CanonicalJSON.
public enum CanonicalJSONError: Error {
    case unsupportedType(String)
    case encodingFailed(String)
}

/// Produces deterministic canonical JSON bytes from a JSON-compatible value.
///
/// Input must be a value that can be round-tripped through JSONSerialization
/// (Dictionary, Array, String, NSNumber, Bool, NSNull / nil, or Data which
/// JSONEncoder encodes as base64-standard).
///
/// This function is the Swift parity of Go's `hcrypto.CanonicalJSON`.
public func canonicalJSON(_ value: Any) throws -> Data {
    let bytes = try marshalCanonical(value)
    return Data(bytes)
}

// MARK: - Internal recursive serialiser

private func marshalCanonical(_ value: Any) throws -> [UInt8] {
    switch value {
    case let dict as [String: Any]:
        return try marshalObject(dict)
    case let array as [Any]:
        return try marshalArray(array)
    case let str as String:
        return try marshalString(str)
    case let bool as Bool:
        // Bool must be checked before NSNumber — in Swift, Bool is bridged to NSNumber
        return bool ? Array("true".utf8) : Array("false".utf8)
    case let num as NSNumber:
        return try marshalNumber(num)
    case is NSNull:
        return Array("null".utf8)
    case Optional<Any>.none:
        return Array("null".utf8)
    default:
        // Attempt JSON serialisation as fallback for NSNumber subclasses, etc.
        let data = try JSONSerialization.data(withJSONObject: value, options: [.fragmentsAllowed])
        return Array(data)
    }
}

private func marshalObject(_ dict: [String: Any]) throws -> [UInt8] {
    let sortedKeys = dict.keys.sorted()
    var buf: [UInt8] = [UInt8(ascii: "{")]
    for (i, key) in sortedKeys.enumerated() {
        if i > 0 { buf.append(UInt8(ascii: ",")) }
        let keyBytes = try marshalString(key)
        buf.append(contentsOf: keyBytes)
        buf.append(UInt8(ascii: ":"))
        let val = dict[key]!
        let valBytes = try marshalCanonical(val)
        buf.append(contentsOf: valBytes)
    }
    buf.append(UInt8(ascii: "}"))
    return buf
}

private func marshalArray(_ array: [Any]) throws -> [UInt8] {
    var buf: [UInt8] = [UInt8(ascii: "[")]
    for (i, item) in array.enumerated() {
        if i > 0 { buf.append(UInt8(ascii: ",")) }
        let itemBytes = try marshalCanonical(item)
        buf.append(contentsOf: itemBytes)
    }
    buf.append(UInt8(ascii: "]"))
    return buf
}

private func marshalString(_ str: String) throws -> [UInt8] {
    // Use JSONSerialization for correct JSON string escaping.
    // .fragmentsAllowed is required for top-level primitives (strings, numbers)
    // on macOS versions before the default changed.
    let data = try JSONSerialization.data(withJSONObject: str, options: [.fragmentsAllowed])
    return Array(data)
}

private func marshalNumber(_ num: NSNumber) throws -> [UInt8] {
    // Preserve integer vs float distinction to match Go encoding/json output.
    // Go encodes integer JSON numbers without decimal point; floats with.
    let cfType = CFGetTypeID(num)
    if cfType == CFBooleanGetTypeID() {
        // Bool sneaks in as NSNumber sometimes.
        return num.boolValue ? Array("true".utf8) : Array("false".utf8)
    }
    let data = try JSONSerialization.data(withJSONObject: num, options: [.fragmentsAllowed])
    return Array(data)
}

// MARK: - Codable → canonical JSON bridge

/// Encodes a Codable value to canonical JSON bytes, ready for Ed25519 signing.
///
/// The value is first encoded via JSONEncoder (with the Hanko wire format
/// settings), then decoded into a generic Any, then re-serialized in canonical
/// form. This matches the Go approach of marshal→unmarshal→marshalCanonical.
public func encodingToCanonicalJSON<T: Encodable>(_ value: T) throws -> Data {
    let encoder = makeHankoEncoder()
    let jsonData = try encoder.encode(value)
    // Round-trip to Any for recursive canonical serialisation.
    let any = try JSONSerialization.jsonObject(with: jsonData, options: [.fragmentsAllowed])
    return try canonicalJSON(any)
}

// MARK: - Hanko JSONEncoder / JSONDecoder factory

/// Returns a JSONEncoder configured for Hanko wire format:
///   - dateEncodingStrategy: iso8601 with fractional seconds disabled
///     (produces "2026-06-06T12:00:00Z" matching Go time.Time RFC3339 UTC).
///   - dataEncodingStrategy: base64 (standard, with padding, matching Go encoding/json []byte).
///   - outputFormatting: withoutEscapingSlashes (no extra escaping).
public func makeHankoEncoder() -> JSONEncoder {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .custom { date, encoderContainer in
        var container = encoderContainer.singleValueContainer()
        let formatted = rfc3339UTCFormatter.string(from: date)
        try container.encode(formatted)
    }
    // Go encoding/json encodes []byte as base64 standard (with padding).
    encoder.dataEncodingStrategy = .base64
    return encoder
}

/// Returns a JSONDecoder configured for Hanko wire format.
public func makeHankoDecoder() -> JSONDecoder {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .custom { decoderContainer in
        let container = try decoderContainer.singleValueContainer()
        let str = try container.decode(String.self)
        guard let date = rfc3339UTCFormatter.date(from: str) ?? parseISO8601WithFractional(str) else {
            throw DecodingError.dataCorruptedError(
                in: container,
                debugDescription: "Invalid RFC3339 date: \(str)"
            )
        }
        return date
    }
    decoder.dataDecodingStrategy = .base64
    return decoder
}

// MARK: - RFC3339 formatters

/// Primary formatter: produces "2026-06-06T12:00:00Z" — matches Go time.Time.UTC().Format(time.RFC3339).
/// nonisolated(unsafe) is safe here: DateFormatter is set up once at module load and never mutated.
nonisolated(unsafe) private let rfc3339UTCFormatter: DateFormatter = {
    let f = DateFormatter()
    f.locale = Locale(identifier: "en_US_POSIX")
    f.timeZone = TimeZone(identifier: "UTC")
    f.dateFormat = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    return f
}()

/// Fallback formatter for timestamps that include nanoseconds or timezone offsets.
/// Wrapped in a struct to satisfy Swift 6 Sendable requirements.
private func parseISO8601WithFractional(_ str: String) -> Date? {
    // Try fractional seconds variant: "2026-06-06T12:00:00.000Z"
    let iso = ISO8601DateFormatter()
    iso.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    if let d = iso.date(from: str) { return d }
    // Also try without fractional seconds but with timezone offset
    let iso2 = ISO8601DateFormatter()
    iso2.formatOptions = [.withInternetDateTime]
    return iso2.date(from: str)
}
