# Design: QUIC Variable-Length Integer Utility

## Issue

GitHub Issue #5: Add variable-length integer encoder/decoder utility for QUIC types

## Goal

Provide a small, self-contained module that encodes and decodes RFC 9000 variable-length integers, so that higher-level HTTP Datagram / MASQUE constructs can build on it.

## Background

RFC 9297 (and RFC 9000 QUIC) use variable-length integers for fields such as Capsule Type, Capsule Length, Quarter Stream ID, and settings values. Before implementing those higher-level constructs, we need a reliable encoder/decoder for the integer representation defined in RFC 9000 Section 16.

## Scope

- Add a `quic_varint` module with:
  - `pub fn encode(value: u64) -> Vec<u8>`
  - `pub fn decode(buf: &[u8]) -> Result<(u64, usize), Error>`
- Support 1-, 2-, 4-, and 8-byte encodings as defined in RFC 9000 Section 16.
- Reject values larger than `2^62 - 1`.
- Reject buffers that are too short to parse.
- Add unit tests covering boundary values, short buffers, and oversized values.
- Ensure `cargo clippy` and `cargo doc` pass with warnings treated as errors.

## Architecture

### File changes

| File | Change |
|---|---|
| `crates/masque/src/quic_varint.rs` | New module implementing `encode` and `decode`. |
| `crates/masque/src/lib.rs` | Add `pub mod quic_varint;` and re-export public items if appropriate. |
| `crates/masque/src/error.rs` | Add `Error::InvalidVarInt { message: String }` variant. |

### Encoding rules

| Value range | Byte length | Leading bits |
|---|---|---|
| `0 ..= 63` | 1 | `0b00` |
| `64 ..= 16_383` | 2 | `0b01` |
| `16_384 ..= 1_073_741_823` | 4 | `0b10` |
| `1_073_741_824 ..= 4_611_686_018_427_387_903` (`2^62 - 1`) | 8 | `0b11` |
| `> 2^62 - 1` | Error | — |

### Decoding rules

1. Reject empty buffers.
2. Read the high two bits of the first byte to determine length.
3. Reject buffers shorter than the indicated length.
4. Reconstruct the integer by clearing the prefix bits and reading the remaining bytes as big-endian.
5. Return `(value, bytes_consumed)`.

### Error handling

A new `Error::InvalidVarInt { message: String }` variant is added to the crate's `Error` enum. This keeps error handling consistent with the existing `InvalidConfig` and `NotImplemented` variants.

`Display` implementation:

```text
invalid varint: {message}
```

### Testing

Unit tests live in `quic_varint.rs` under `#[cfg(test)] mod tests`.

Test cases:

- Round-trip for boundary values:
  - `0`
  - `63`
  - `64`
  - `16_383`
  - `16_384`
  - `1_073_741_823`
  - `1_073_741_824`
  - `4_611_686_018_427_387_903` (`2^62 - 1`)
- Encode rejects values `>= 2^62`.
- Decode rejects empty buffers.
- Decode rejects buffers shorter than the indicated length for each encoding size.

## Dependencies

No new external dependencies. The implementation uses only the standard library.

## Acceptance Criteria

- [ ] `quic_varint::encode` and `quic_varint::decode` are implemented and documented.
- [ ] Edge cases (max value, minimum buffer length, oversized values) are covered by unit tests.
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` passes.
- [ ] `RUSTDOCFLAGS=-D warnings cargo doc --workspace --no-deps --document-private-items --locked` passes.

## References

- RFC 9000 Section 16: <https://datatracker.ietf.org/doc/html/rfc9000#section-16>
- RFC 9297 Section 1.1: <https://datatracker.ietf.org/doc/html/rfc9297#section-1.1>
