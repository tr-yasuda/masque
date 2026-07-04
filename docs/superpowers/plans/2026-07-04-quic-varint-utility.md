# QUIC Variable-Length Integer Utility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a self-contained `quic_varint` module that encodes and decodes RFC 9000 variable-length integers, exposed through the `masque` crate's public API.

**Architecture:** Add a new `InvalidVarInt` error variant to the existing `Error` enum, create a focused `quic_varint` module with `encode`/`decode` functions, and re-export it from `lib.rs`. The module is pure standard-library Rust with no external dependencies.

**Tech Stack:** Rust 2024 edition, Cargo workspace, built-in `#[cfg(test)]` unit tests.

---

## File Structure

| File | Responsibility |
|---|---|
| `crates/masque/src/error.rs` | Add `Error::InvalidVarInt` variant and its `Display` formatting. |
| `crates/masque/src/quic_varint.rs` | New module containing `encode`, `decode`, and their unit tests. |
| `crates/masque/src/lib.rs` | Re-export the new `quic_varint` module. |

---

## Task 1: Add `InvalidVarInt` error variant

**Files:**
- Modify: `crates/masque/src/error.rs`
- Test: `crates/masque/src/error.rs` (existing `#[cfg(test)] mod tests`)

- [ ] **Step 1: Write the failing test**

Add the following test to the existing `#[cfg(test)] mod tests` block in `crates/masque/src/error.rs`:

```rust
#[test]
fn invalid_var_int_display_includes_message() {
    let err = Error::InvalidVarInt {
        message: "value too large".into(),
    };
    assert_eq!(err.to_string(), "invalid varint: value too large");
}
```

- [ ] **Step 2: Run the failing test**

Run:

```bash
cargo test --package masque invalid_var_int_display_includes_message -- --exact
```

Expected: compilation failure because `InvalidVarInt` does not exist.

- [ ] **Step 3: Add the `InvalidVarInt` variant**

Insert this arm into the `Error` enum in `crates/masque/src/error.rs` between `InvalidConfig` and `NotImplemented`:

```rust
/// The variable-length integer encoding or decoding failed.
InvalidVarInt {
    /// A human-readable description of what is wrong.
    message: String,
},
```

Add this arm to the `fmt::Display` implementation:

```rust
Error::InvalidVarInt { message } => write!(f, "invalid varint: {message}"),
```

- [ ] **Step 4: Run the passing test**

Run:

```bash
cargo test --package masque invalid_var_int_display_includes_message -- --exact
```

Expected: test passes.

- [ ] **Step 5: Commit**

```bash
git add crates/masque/src/error.rs
git commit -m "feat: add InvalidVarInt error variant"
```

---

## Task 2: Implement `quic_varint::encode`

**Files:**
- Create: `crates/masque/src/quic_varint.rs`
- Modify: `crates/masque/src/quic_varint.rs`

- [ ] **Step 1: Write the failing tests**

Create `crates/masque/src/quic_varint.rs` with this initial test module:

```rust
//! QUIC variable-length integer encoding and decoding (RFC 9000 Section 16).

use crate::error::{Error, Result};

/// Maximum value representable by a QUIC variable-length integer.
const MAX_VARINT: u64 = 4_611_686_018_427_387_903; // 2^62 - 1

/// Encodes a value as a QUIC variable-length integer.
///
/// # Panics
///
/// Panics if `value` is greater than `2^62 - 1`.
pub fn encode(value: u64) -> Vec<u8> {
    todo!()
}

/// Decodes a QUIC variable-length integer from a byte buffer.
///
/// Returns the decoded value and the number of bytes consumed.
pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_uses_one_byte_for_small_values() {
        assert_eq!(encode(0), vec![0x00]);
        assert_eq!(encode(63), vec![0x3f]);
    }

    #[test]
    fn encode_uses_two_bytes_for_medium_values() {
        assert_eq!(encode(64), vec![0x40, 0x40]);
        assert_eq!(encode(16_383), vec![0x7f, 0xff]);
    }

    #[test]
    fn encode_uses_four_bytes_for_large_values() {
        assert_eq!(encode(16_384), vec![0x80, 0x00, 0x40, 0x00]);
        assert_eq!(encode(1_073_741_823), vec![0xbf, 0xff, 0xff, 0xff]);
    }

    #[test]
    fn encode_uses_eight_bytes_for_huge_values() {
        assert_eq!(
            encode(1_073_741_824),
            vec![0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]
        );
        assert_eq!(
            encode(MAX_VARINT),
            vec![0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
    }

    #[test]
    #[should_panic(expected = "value exceeds 2^62 - 1")]
    fn encode_panics_on_oversized_values() {
        encode(MAX_VARINT + 1);
    }
}
```

- [ ] **Step 2: Run the failing tests**

Run:

```bash
cargo test --package masque quic_varint::tests -- --test-threads=1
```

Expected: tests fail because `encode` panics with `todo!()`.

- [ ] **Step 3: Implement `encode`**

Replace the `todo!()` body of `encode` in `crates/masque/src/quic_varint.rs` with:

```rust
pub fn encode(value: u64) -> Vec<u8> {
    assert!(value <= MAX_VARINT, "value exceeds 2^62 - 1");

    if value <= 0x3f {
        vec![value as u8]
    } else if value <= 0x3fff {
        (value | 0x4000).to_be_bytes()[2..].to_vec()
    } else if value <= 0x3fffffff {
        (value | 0x80000000).to_be_bytes().to_vec()
    } else {
        (value | 0xc000000000000000).to_be_bytes().to_vec()
    }
}
```

- [ ] **Step 4: Run the passing tests**

Run:

```bash
cargo test --package masque quic_varint::tests -- --test-threads=1
```

Expected: all encode tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/masque/src/quic_varint.rs
git commit -m "feat: implement quic_varint encode"
```

---

## Task 3: Implement `quic_varint::decode`

**Files:**
- Modify: `crates/masque/src/quic_varint.rs`

- [ ] **Step 1: Write the failing tests**

Append the following tests to the existing `tests` module in `crates/masque/src/quic_varint.rs`:

```rust
#[test]
fn decode_round_trips_boundary_values() {
    let values = [
        0u64,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        MAX_VARINT,
    ];
    for value in values {
        let encoded = encode(value);
        let (decoded, consumed) = decode(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn decode_rejects_empty_buffer() {
    let err = decode(&[]).unwrap_err();
    assert_eq!(err.to_string(), "invalid varint: empty buffer");
}

#[test]
fn decode_rejects_short_buffer_for_two_byte_form() {
    let err = decode(&[0x40]).unwrap_err();
    assert_eq!(err.to_string(), "invalid varint: buffer too short");
}

#[test]
fn decode_rejects_short_buffer_for_four_byte_form() {
    let err = decode(&[0x80, 0x00, 0x00]).unwrap_err();
    assert_eq!(err.to_string(), "invalid varint: buffer too short");
}

#[test]
fn decode_rejects_short_buffer_for_eight_byte_form() {
    let err = decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).unwrap_err();
    assert_eq!(err.to_string(), "invalid varint: buffer too short");
}
```

- [ ] **Step 2: Run the failing tests**

Run:

```bash
cargo test --package masque quic_varint::tests -- --test-threads=1
```

Expected: new decode tests fail because `decode` panics with `todo!()`.

- [ ] **Step 3: Implement `decode`**

Replace the `todo!()` body of `decode` in `crates/masque/src/quic_varint.rs` with:

```rust
pub fn decode(buf: &[u8]) -> Result<(u64, usize)> {
    if buf.is_empty() {
        return Err(Error::InvalidVarInt {
            message: "empty buffer".into(),
        });
    }

    let first = buf[0];
    let (len, mask) = match first >> 6 {
        0b00 => (1, 0x3f),
        0b01 => (2, 0x3fff),
        0b10 => (4, 0x3fffffff),
        0b11 => (8, 0x3fffffffffffffff),
        _ => unreachable!(),
    };

    if buf.len() < len {
        return Err(Error::InvalidVarInt {
            message: "buffer too short".into(),
        });
    }

    let mut bytes = [0u8; 8];
    bytes[8 - len..].copy_from_slice(&buf[..len]);
    let value = u64::from_be_bytes(bytes) & mask;

    Ok((value, len))
}
```

- [ ] **Step 4: Run the passing tests**

Run:

```bash
cargo test --package masque quic_varint::tests -- --test-threads=1
```

Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add crates/masque/src/quic_varint.rs
git commit -m "feat: implement quic_varint decode"
```

---

## Task 4: Re-export the module from `lib.rs`

**Files:**
- Modify: `crates/masque/src/lib.rs`

- [ ] **Step 1: Add the module re-export**

In `crates/masque/src/lib.rs`, add `pub mod quic_varint;` below the existing module declarations and add a `pub use` line if desired:

```rust
pub mod config;
pub mod error;
pub mod quic_varint;
pub mod types;

pub use config::Config;
pub use error::{Error, Result};
pub use types::{Protocol, Session};
```

- [ ] **Step 2: Verify the public API compiles**

Run:

```bash
cargo build --package masque
```

Expected: build succeeds.

- [ ] **Step 3: Commit**

```bash
git add crates/masque/src/lib.rs
git commit -m "feat: re-export quic_varint module"
```

---

## Task 5: Run full validation suite

**Files:**
- All of the above

- [ ] **Step 1: Format check**

Run:

```bash
cargo fmt --all -- --check
```

Expected: no formatting issues.

- [ ] **Step 2: Clippy**

Run:

```bash
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected: no warnings or errors.

- [ ] **Step 3: Documentation**

Run:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked
```

Expected: no warnings or errors.

- [ ] **Step 4: Tests**

Run:

```bash
cargo test --workspace --locked
```

Expected: all tests pass.

- [ ] **Step 5: Commit any fixes**

If any step produced fixes, commit them with a descriptive message such as:

```bash
git add .
git commit -m "style: address clippy and rustdoc warnings"
```

---

## Self-Review Checklist

- [ ] Spec coverage: every acceptance criterion in the design doc maps to a task above.
- [ ] Placeholder scan: no `TODO`, `TBD`, or vague steps remain.
- [ ] Type consistency: `encode` and `decode` signatures match the design doc throughout.
