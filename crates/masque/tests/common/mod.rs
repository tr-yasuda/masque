//! Shared helpers for capsule-stream integration tests.

use masque::{Capsule, CapsuleParser};

/// An arbitrary unknown capsule type used across tests.
pub const UNKNOWN_CAPSULE_TYPE: u64 = 0x2bad;

/// Chunk size used to feed bytes into [`CapsuleParser`].
///
/// This value is intentionally small and unrelated to varint boundaries so that
/// every test exercises incremental parsing across type/length/value splits.
pub const FEED_CHUNK_SIZE: usize = 7;

/// Encode a sequence of capsules into a single byte stream.
#[allow(dead_code)]
pub fn encode_capsule_stream(capsules: &[Capsule]) -> Vec<u8> {
    let mut buf = Vec::new();
    for capsule in capsules {
        buf.extend_from_slice(&capsule.encode().unwrap());
    }
    buf
}

/// Feed `bytes` into a fresh [`CapsuleParser`] in small chunks and return all
/// known capsules that were yielded.
///
/// Unknown capsule types are silently skipped, matching RFC 9297 Section 3.2.
/// Parse errors are propagated as `Err` so callers can inspect them in
/// error-path tests.
pub fn parse_known_capsules(bytes: &[u8]) -> Result<Vec<Capsule>, masque::Error> {
    let mut parser = CapsuleParser::new();
    let mut capsules = Vec::new();

    for chunk in bytes.chunks(FEED_CHUNK_SIZE) {
        if let Some(capsule) = parser.feed(chunk)? {
            capsules.push(capsule);
        }
        while let Some(capsule) = parser.next_capsule()? {
            capsules.push(capsule);
        }
    }

    while let Some(capsule) = parser.next_capsule()? {
        capsules.push(capsule);
    }

    parser.finalize()?;
    Ok(capsules)
}
