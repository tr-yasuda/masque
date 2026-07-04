//! Capsule Protocol types and serialization (RFC 9297 Section 3.2).

use crate::error::VarIntErrorKind;
use crate::quic_varint::{self, MAX_VARINT};
use crate::{Error, H3DatagramErrorKind, Result};

/// A Capsule Protocol type identifier.
///
/// This is a validated newtype: values are guaranteed to be representable as a
/// QUIC variable-length integer (`0..=MAX_VARINT`). The known DATAGRAM type
/// (`0x00`) is exposed as [`CapsuleType::DATAGRAM`]; any other value is treated
/// as an unknown type and preserved so that receivers can skip it without
/// aborting the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CapsuleType(u64);

impl CapsuleType {
    /// The DATAGRAM capsule type (`0x00`).
    pub const DATAGRAM: Self = Self(0);

    /// Create a `CapsuleType` from its raw numeric value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::VarintOutOfRange`] if `value` is greater than
    /// [`MAX_VARINT`].
    pub fn new(value: u64) -> Result<Self> {
        if value > MAX_VARINT {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::VarintOutOfRange,
                format!("capsule type {value} exceeds maximum varint value"),
            ));
        }
        Ok(Self(value))
    }

    /// Return the raw numeric capsule type.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }

    /// Return whether this is the known DATAGRAM type.
    #[must_use]
    pub const fn is_datagram(self) -> bool {
        self.0 == 0
    }

    /// Return whether this is an unknown capsule type.
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        self.0 != 0
    }
}

/// A Capsule Protocol message.
///
/// Each capsule consists of a type, a length, and a value. The length is
/// derived from the value and is serialized as a QUIC variable-length integer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capsule {
    capsule_type: CapsuleType,
    value: Vec<u8>,
}

impl Capsule {
    /// Create a new capsule from a type and value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] with kind
    /// [`H3DatagramErrorKind::VarintOutOfRange`] if the value length cannot be
    /// encoded as a QUIC variable-length integer.
    pub fn new(capsule_type: CapsuleType, value: Vec<u8>) -> Result<Self> {
        validate_length(value.len())?;
        Ok(Self {
            capsule_type,
            value,
        })
    }

    /// Return the capsule type.
    #[must_use]
    pub const fn capsule_type(&self) -> CapsuleType {
        self.capsule_type
    }

    /// Return the capsule length (the number of bytes in the value).
    #[must_use]
    pub fn length(&self) -> u64 {
        self.value.len() as u64
    }

    /// Return the capsule value.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Consume the capsule and return its value.
    #[must_use]
    pub fn into_value(self) -> Vec<u8> {
        self.value
    }

    /// Encode the capsule into a byte vector.
    ///
    /// The encoded form is `Capsule Type (i) | Capsule Length (i) | Capsule Value (...)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidVarInt`] only if an internal invariant is
    /// violated; this cannot happen for values produced through [`Capsule::new`].
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut type_buf = [0u8; 8];
        let type_len = quic_varint::encode_into(self.capsule_type.value(), &mut type_buf)?;

        let mut length_buf = [0u8; 8];
        let length_len = quic_varint::encode_into(self.length(), &mut length_buf)?;

        let mut out = Vec::with_capacity(type_len + length_len + self.value.len());
        out.extend_from_slice(&type_buf[..type_len]);
        out.extend_from_slice(&length_buf[..length_len]);
        out.extend_from_slice(&self.value);
        Ok(out)
    }

    /// Serialize the capsule into a caller-provided buffer.
    ///
    /// Writes the capsule type varint, length varint, and value bytes in order.
    /// Returns the total number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidVarInt`] with [`VarIntErrorKind::BufferTooShort`]
    /// if `buf` is too small to hold the serialized capsule. May also return
    /// [`Error::H3DatagramError`] with [`H3DatagramErrorKind::LengthOverflow`]
    /// if the serialized size overflows `usize`.
    pub fn encode_into(&self, buf: &mut [u8]) -> Result<usize> {
        let type_len = varint_len(self.capsule_type.value());
        let length_len = varint_len(self.length());
        let value_len = self.value().len();
        let total_len = type_len
            .checked_add(length_len)
            .and_then(|n| n.checked_add(value_len))
            .ok_or_else(|| {
                Error::h3_datagram_error(
                    H3DatagramErrorKind::LengthOverflow,
                    "encoded capsule overflow",
                )
            })?;
        if buf.len() < total_len {
            return Err(Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                message: "output buffer too short".into(),
            });
        }

        let mut offset = 0;
        offset += quic_varint::encode_into_at(self.capsule_type.value(), buf, offset)?;
        offset += quic_varint::encode_into_at(self.length(), buf, offset)?;
        buf[offset..offset + value_len].copy_from_slice(self.value());
        Ok(total_len)
    }

    /// Decode a capsule from a byte buffer.
    ///
    /// Returns the decoded capsule and the number of bytes consumed.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] if the buffer does not contain a
    /// well-formed capsule. This includes malformed capsule type/length varints,
    /// a length that overflows `usize`, an offset overflow, or a truncated value.
    pub fn decode(buf: &[u8]) -> Result<(Self, usize)> {
        let (capsule_type_value, mut offset) = quic_varint::decode(buf).map_err(map_varint_err)?;
        let capsule_type = CapsuleType::new(capsule_type_value)?;

        let (length, consumed) = quic_varint::decode_at(buf, offset).map_err(map_varint_err)?;
        offset += consumed;

        let length = usize::try_from(length).map_err(|_| {
            Error::h3_datagram_error(
                H3DatagramErrorKind::LengthTooLarge,
                "capsule length exceeds platform usize",
            )
        })?;

        let end = offset.checked_add(length).ok_or_else(|| {
            Error::h3_datagram_error(
                H3DatagramErrorKind::LengthOverflow,
                "capsule length overflow",
            )
        })?;

        if buf.len() < end {
            return Err(Error::h3_datagram_error(
                H3DatagramErrorKind::Truncated,
                "capsule value truncated",
            ));
        }

        let value = buf[offset..end].to_vec();
        Ok((
            Self {
                capsule_type,
                value,
            },
            end,
        ))
    }
}

/// Default maximum capsule value length accepted by [`CapsuleParser`].
pub const DEFAULT_MAX_CAPSULE_LENGTH: usize = 65_536;

/// A push-style streaming parser for Capsule Protocol messages.
///
/// The parser buffers only unconsumed bytes. Callers feed newly received bytes
/// with [`CapsuleParser::feed`]; when a complete capsule is available the
/// method returns `Ok(Some(Capsule))`. If more bytes are needed it returns
/// `Ok(None)`.
///
/// Capsules with unknown types are silently skipped as required by RFC 9297
/// Section 3.2. Their value bytes are not copied into a [`Capsule`]; once the
/// capsule header has been parsed, received value bytes are discarded from the
/// internal buffer as they arrive. This bounds the memory used for a skipped
/// capsule to the header size plus at most one feed chunk, rather than the
/// declared capsule length.
///
/// Note that the parser still buffers one complete capsule value before
/// yielding it, because [`Capsule`] stores the value as a [`Vec<u8>`]. The
/// streaming improvement is avoiding buffering the *entire* byte stream, not
/// avoiding buffering an individual capsule value.
///
/// The default maximum accepted capsule value length is
/// [`DEFAULT_MAX_CAPSULE_LENGTH`]. Use [`CapsuleParser::with_max_length`] to
/// configure a different limit. `Clone` performs a deep copy of the internal
/// buffer, which can be expensive if a large partial capsule is buffered.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CapsuleParser {
    buf: Vec<u8>,
    /// Number of consumed prefix bytes in `buf`.
    start: usize,
    max_capsule_length: usize,
    /// Remaining bytes of an unknown capsule value to discard.
    skip_remaining: usize,
}

impl Default for CapsuleParser {
    fn default() -> Self {
        Self::with_max_length(DEFAULT_MAX_CAPSULE_LENGTH)
    }
}

impl CapsuleParser {
    /// Create a new empty parser with the default maximum capsule length.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new empty parser with a custom maximum capsule value length.
    ///
    /// Capsules whose declared length exceeds `max_capsule_length` are rejected
    /// with [`H3DatagramErrorKind::LengthTooLarge`].
    pub fn with_max_length(max_capsule_length: usize) -> Self {
        Self {
            buf: Vec::new(),
            start: 0,
            max_capsule_length,
            skip_remaining: 0,
        }
    }

    /// Return the maximum capsule value length accepted by this parser.
    #[must_use]
    pub const fn max_capsule_length(&self) -> usize {
        self.max_capsule_length
    }

    /// Feed bytes into the parser and try to emit one complete capsule.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] if the buffered bytes describe a
    /// malformed capsule header (length too large, type out of range, etc.).
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Option<Capsule>> {
        self.buf.extend_from_slice(bytes);
        self.try_parse()
    }

    /// Try to emit the next buffered capsule without feeding new bytes.
    ///
    /// This is useful when a single [`CapsuleParser::feed`] call returns one
    /// capsule but more complete capsules remain in the internal buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramError`] if the buffered bytes describe a
    /// malformed capsule header.
    pub fn next_capsule(&mut self) -> Result<Option<Capsule>> {
        self.try_parse()
    }

    /// Signal the end of the stream and verify that no partial capsule remains.
    ///
    /// Returns `Ok(())` if the internal buffer is empty. If any bytes are left
    /// buffered when the stream ends, returns [`Error::H3DatagramError`] with
    /// kind [`H3DatagramErrorKind::Truncated`], mirroring the behavior of
    /// [`Capsule::decode`] for a truncated final capsule.
    pub fn finalize(self) -> Result<()> {
        if self.start >= self.buf.len() && self.skip_remaining == 0 {
            Ok(())
        } else {
            Err(Error::h3_datagram_error(
                H3DatagramErrorKind::Truncated,
                "capsule truncated at end of stream",
            ))
        }
    }

    fn try_parse(&mut self) -> Result<Option<Capsule>> {
        loop {
            if self.skip_remaining > 0 {
                let available = self.buf.len().saturating_sub(self.start);
                let discard = available.min(self.skip_remaining);
                self.start += discard;
                self.skip_remaining -= discard;
                self.maybe_compact();
                if self.skip_remaining > 0 {
                    return Ok(None);
                }
            }

            let window = match self.buf.get(self.start..) {
                Some(w) if !w.is_empty() => w,
                _ => {
                    self.compact();
                    return Ok(None);
                }
            };

            let (capsule_type_value, type_len) = match quic_varint::decode(window) {
                Ok(v) => v,
                Err(err) if is_incomplete_varint(&err) => return Ok(None),
                Err(err) => return Err(map_varint_err(err)),
            };
            let capsule_type = CapsuleType::new(capsule_type_value)?;

            let (length, length_len) = match quic_varint::decode_at(window, type_len) {
                Ok(v) => v,
                Err(err) if is_incomplete_varint(&err) => return Ok(None),
                Err(err) => return Err(map_varint_err(err)),
            };

            let length = usize::try_from(length).map_err(|_| {
                Error::h3_datagram_error(
                    H3DatagramErrorKind::LengthTooLarge,
                    "capsule length exceeds platform usize",
                )
            })?;

            let header_len = type_len + length_len;
            let end = header_len.checked_add(length).ok_or_else(|| {
                Error::h3_datagram_error(
                    H3DatagramErrorKind::LengthOverflow,
                    "capsule length overflow",
                )
            })?;

            if capsule_type.is_unknown() {
                if window.len() >= end {
                    // The whole unknown capsule is already buffered; skip it now.
                    self.start += end;
                    self.maybe_compact();
                    continue;
                }

                // Only part of the value has arrived. Discard the header and any
                // value bytes already present, then drain the rest incrementally
                // as more bytes are fed.
                let available_value = window.len().saturating_sub(header_len);
                self.start += header_len + available_value;
                self.skip_remaining = length.saturating_sub(available_value);
                self.maybe_compact();
                return Ok(None);
            }

            if length > self.max_capsule_length {
                return Err(Error::h3_datagram_error(
                    H3DatagramErrorKind::LengthTooLarge,
                    "capsule length exceeds maximum allowed",
                ));
            }

            if window.len() < end {
                return Ok(None);
            }

            let value_start = self.start + header_len;
            let value_end = self.start + end;
            let value = self.buf[value_start..value_end].to_vec();
            self.start += end;
            self.maybe_compact();
            return Ok(Some(Capsule::new(capsule_type, value)?));
        }
    }

    fn maybe_compact(&mut self) {
        const COMPACT_THRESHOLD: usize = 1024;
        if self.start >= COMPACT_THRESHOLD {
            self.compact();
        }
    }

    fn compact(&mut self) {
        if self.start == self.buf.len() {
            self.buf.clear();
        } else {
            self.buf.drain(..self.start);
        }
        self.start = 0;
    }
}

fn validate_length(len: usize) -> Result<()> {
    let len_u64 = u64::try_from(len).map_err(|_| {
        Error::h3_datagram_error(
            H3DatagramErrorKind::LengthTooLarge,
            "capsule value length exceeds u64",
        )
    })?;
    if len_u64 > MAX_VARINT {
        return Err(Error::h3_datagram_error(
            H3DatagramErrorKind::VarintOutOfRange,
            "capsule value length exceeds maximum varint",
        ));
    }
    Ok(())
}

fn map_varint_err(err: Error) -> Error {
    Error::h3_datagram_error_with_source(
        H3DatagramErrorKind::InvalidVarint,
        "malformed capsule varint",
        err,
    )
}

fn is_incomplete_varint(err: &Error) -> bool {
    matches!(
        err,
        Error::InvalidVarInt {
            kind: VarIntErrorKind::BufferTooShort
                | VarIntErrorKind::EmptyBuffer
                | VarIntErrorKind::OffsetOutOfBounds,
            ..
        }
    )
}

fn varint_len(value: u64) -> usize {
    match value {
        0..=0x3f => 1,
        0x40..=0x3fff => 2,
        0x4000..=0x3fffffff => 4,
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_type_datagram_value_is_zero() {
        assert_eq!(CapsuleType::DATAGRAM.value(), 0);
        assert!(CapsuleType::DATAGRAM.is_datagram());
        assert!(!CapsuleType::DATAGRAM.is_unknown());
        assert_eq!(CapsuleType::new(0).unwrap(), CapsuleType::DATAGRAM);
    }

    #[test]
    fn capsule_type_unknown_preserves_value() {
        let t = CapsuleType::new(0xff).unwrap();
        assert!(t.is_unknown());
        assert!(!t.is_datagram());
        assert_eq!(t.value(), 0xff);
    }

    #[test]
    fn capsule_type_known_and_unknown_values_differ() {
        assert_eq!(CapsuleType::DATAGRAM, CapsuleType::new(0).unwrap());
        assert_ne!(CapsuleType::DATAGRAM, CapsuleType::new(1).unwrap());
        assert_ne!(CapsuleType::new(1).unwrap(), CapsuleType::new(2).unwrap());
    }

    #[test]
    fn capsule_type_rejects_out_of_range_value() {
        let err = CapsuleType::new(MAX_VARINT + 1).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::VarintOutOfRange,
                ..
            }
        ));
        assert!(err.to_string().contains("capsule type"));
    }

    #[test]
    fn capsule_stores_type_length_and_value() {
        let value = vec![0x01, 0x02, 0x03];
        let capsule = Capsule::new(CapsuleType::DATAGRAM, value.clone()).unwrap();
        assert_eq!(capsule.capsule_type(), CapsuleType::DATAGRAM);
        assert_eq!(capsule.length(), 3);
        assert_eq!(capsule.value(), &value[..]);
        assert_eq!(capsule.into_value(), value);
    }

    #[test]
    fn capsule_encode_decode_round_trips_datagram() {
        let value = vec![0xab, 0xcd];
        let original = Capsule::new(CapsuleType::DATAGRAM, value).unwrap();
        let encoded = original.encode().unwrap();
        let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn capsule_encode_decode_round_trips_unknown_type() {
        let value = vec![0x00, 0x11, 0x22];
        let original = Capsule::new(CapsuleType::new(0x2bad).unwrap(), value).unwrap();
        let encoded = original.encode().unwrap();
        let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
    }

    #[test]
    fn capsule_encode_decode_round_trips_empty_value() {
        let original = Capsule::new(CapsuleType::DATAGRAM, vec![]).unwrap();
        let encoded = original.encode().unwrap();
        assert_eq!(encoded, vec![0x00, 0x00]);
        let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, encoded.len());
        assert_eq!(decoded, original);
        assert_eq!(decoded.length(), 0);
    }

    #[test]
    fn capsule_encode_decode_round_trips_varint_length_boundaries() {
        for len in [63usize, 64, 16383, 16384] {
            let value = vec![0u8; len];
            let original = Capsule::new(CapsuleType::DATAGRAM, value).unwrap();
            let encoded = original.encode().unwrap();
            let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
            assert_eq!(
                consumed,
                encoded.len(),
                "consumed bytes mismatch for value length {len}"
            );
            assert_eq!(decoded.length(), len as u64);
            assert_eq!(decoded.value().len(), len);
        }
    }

    #[test]
    fn capsule_decode_rejects_truncated_value() {
        // Type = 0x00, Length = 0x05, but only 2 value bytes follow.
        let encoded = [0x00, 0x05, 0x01, 0x02];
        let err = Capsule::decode(&encoded).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::Truncated,
                ..
            }
        ));
        assert!(err.to_string().contains("truncated"));
    }

    #[test]
    fn capsule_decode_wraps_truncated_header_in_h3_datagram_error() {
        let err = Capsule::decode(&[0xc0]).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::InvalidVarint,
                ..
            }
        ));
        assert!(err.to_string().contains("malformed capsule varint"));
    }

    #[test]
    fn capsule_decode_stops_at_end_of_capsule_with_trailing_bytes() {
        // DATAGRAM capsule with 2-byte value, followed by trailing bytes.
        let encoded = [0x00, 0x02, 0x01, 0x02, 0xff, 0xff];
        let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
        assert_eq!(consumed, 4);
        assert_eq!(decoded.value(), &[0x01, 0x02]);
    }

    #[test]
    fn capsule_encode_into_matches_encode() {
        let value = vec![0xab, 0xcd, 0xef];
        let capsule = Capsule::new(CapsuleType::DATAGRAM, value).unwrap();
        let encoded = capsule.encode().unwrap();
        let mut buf = vec![0u8; encoded.len()];
        let written = capsule.encode_into(&mut buf).unwrap();
        assert_eq!(written, encoded.len());
        assert_eq!(&buf[..written], &encoded);
    }

    #[test]
    fn capsule_encode_into_rejects_short_buffer() {
        let capsule = Capsule::new(CapsuleType::DATAGRAM, vec![0x01, 0x02]).unwrap();
        let mut buf = [0u8; 1];
        let err = capsule.encode_into(&mut buf).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                ..
            }
        ));
    }

    #[test]
    fn parser_returns_none_for_incomplete_type() {
        // 0xc0 starts an 8-byte varint but only 1 byte is supplied.
        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&[0xc0]).unwrap(), None);
    }

    #[test]
    fn parser_returns_none_for_incomplete_length() {
        // Type = 0x00, length varint incomplete (0xc0 starts 8-byte form).
        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&[0x00, 0xc0]).unwrap(), None);
    }

    #[test]
    fn parser_returns_none_for_incomplete_value() {
        // Type = 0x00, length = 0x05, only 2 value bytes.
        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&[0x00, 0x05, 0x01, 0x02]).unwrap(), None);
    }

    #[test]
    fn parser_decodes_after_multiple_feeds() {
        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&[0x00]).unwrap(), None);
        assert_eq!(parser.feed(&[0x03, 0x01]).unwrap(), None);
        let capsule = parser.feed(&[0x02, 0x03]).unwrap().unwrap();
        assert_eq!(capsule.capsule_type(), CapsuleType::DATAGRAM);
        assert_eq!(capsule.value(), &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn parser_decodes_empty_value_capsule() {
        let mut parser = CapsuleParser::new();
        let capsule = parser.feed(&[0x00, 0x00]).unwrap().unwrap();
        assert_eq!(capsule.capsule_type(), CapsuleType::DATAGRAM);
        assert_eq!(capsule.value(), &[]);
    }

    #[test]
    fn parser_decodes_multiple_capsules_in_one_feed() {
        let a = Capsule::new(CapsuleType::DATAGRAM, vec![0x01]).unwrap();
        let b = Capsule::new(CapsuleType::DATAGRAM, vec![0x02, 0x03]).unwrap();
        let mut encoded = a.encode().unwrap();
        encoded.extend_from_slice(&b.encode().unwrap());

        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&encoded).unwrap(), Some(a));
        assert_eq!(parser.feed(&[]).unwrap(), Some(b));
        assert_eq!(parser.feed(&[]).unwrap(), None);
    }

    #[test]
    fn parser_next_capsule_drains_buffered_capsules() {
        let a = Capsule::new(CapsuleType::DATAGRAM, vec![0x01]).unwrap();
        let b = Capsule::new(CapsuleType::DATAGRAM, vec![0x02, 0x03]).unwrap();
        let mut encoded = a.encode().unwrap();
        encoded.extend_from_slice(&b.encode().unwrap());

        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&encoded).unwrap(), Some(a));
        assert_eq!(parser.next_capsule().unwrap(), Some(b));
        assert_eq!(parser.next_capsule().unwrap(), None);
    }

    #[test]
    fn parser_rejects_length_exceeding_max() {
        let mut parser = CapsuleParser::with_max_length(4);
        // Type = 0x00, Length = 0x05, value = 5 bytes (exceeds max 4).
        let err = parser
            .feed(&[0x00, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05])
            .unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::LengthTooLarge,
                ..
            }
        ));
    }

    #[test]
    fn parser_decodes_varint_length_boundaries_across_feeds() {
        for len in [63usize, 64, 16383, 16384] {
            let capsule = Capsule::new(CapsuleType::DATAGRAM, vec![0u8; len]).unwrap();
            let encoded = capsule.encode().unwrap();

            let mut parser = CapsuleParser::new();
            let mut decoded = None;
            for chunk in encoded.chunks(7) {
                if let Some(c) = parser.feed(chunk).unwrap() {
                    decoded = Some(c);
                }
            }
            let decoded =
                decoded.unwrap_or_else(|| panic!("should decode a capsule for length {len}"));
            assert_eq!(decoded.capsule_type(), CapsuleType::DATAGRAM);
            assert_eq!(decoded.value().len(), len);
            assert_eq!(parser.feed(&[]).unwrap(), None);
        }
    }

    #[test]
    fn encode_into_does_not_partially_write_on_short_buffer() {
        let capsule = Capsule::new(CapsuleType::DATAGRAM, vec![0x01, 0x02]).unwrap();
        let mut buf = [0x9fu8; 3];
        let err = capsule.encode_into(&mut buf).unwrap_err();
        assert!(matches!(
            err,
            Error::InvalidVarInt {
                kind: VarIntErrorKind::BufferTooShort,
                ..
            }
        ));
        assert_eq!(buf, [0x9f; 3]);
    }

    #[test]
    fn finalize_accepts_empty_buffer() {
        let parser = CapsuleParser::new();
        assert!(parser.finalize().is_ok());
    }

    #[test]
    fn finalize_rejects_partial_type() {
        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&[0xc0]).unwrap(), None);
        let err = parser.finalize().unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::Truncated,
                ..
            }
        ));
    }

    #[test]
    fn finalize_rejects_partial_length() {
        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&[0x00, 0xc0]).unwrap(), None);
        let err = parser.finalize().unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::Truncated,
                ..
            }
        ));
    }

    #[test]
    fn finalize_rejects_partial_value() {
        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&[0x00, 0x05, 0x01, 0x02]).unwrap(), None);
        let err = parser.finalize().unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::Truncated,
                ..
            }
        ));
    }
    #[test]
    fn parser_silently_skips_unknown_capsule_type() {
        let known = Capsule::new(CapsuleType::DATAGRAM, vec![0x01]).unwrap();
        let unknown = Capsule::new(CapsuleType::new(0x2bad).unwrap(), vec![0xab, 0xcd]).unwrap();

        let mut encoded = known.encode().unwrap();
        encoded.extend_from_slice(&unknown.encode().unwrap());

        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&encoded).unwrap(), Some(known));
        assert_eq!(parser.feed(&[]).unwrap(), None);
    }

    #[test]
    fn parser_skips_unknown_capsule_at_start_of_stream() {
        let unknown = Capsule::new(CapsuleType::new(0x2bad).unwrap(), vec![0xab]).unwrap();
        let known = Capsule::new(CapsuleType::DATAGRAM, vec![0x01, 0x02]).unwrap();

        let mut encoded = unknown.encode().unwrap();
        encoded.extend_from_slice(&known.encode().unwrap());

        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&encoded).unwrap(), Some(known));
        assert_eq!(parser.feed(&[]).unwrap(), None);
    }

    #[test]
    fn parser_skips_consecutive_unknown_capsule_types() {
        let unknown1 = Capsule::new(CapsuleType::new(0x2bad).unwrap(), vec![0x01]).unwrap();
        let unknown2 = Capsule::new(CapsuleType::new(0x2bae).unwrap(), vec![0x02]).unwrap();
        let known = Capsule::new(CapsuleType::DATAGRAM, vec![0x03]).unwrap();

        let mut encoded = unknown1.encode().unwrap();
        encoded.extend_from_slice(&unknown2.encode().unwrap());
        encoded.extend_from_slice(&known.encode().unwrap());

        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&encoded).unwrap(), Some(known));
        assert_eq!(parser.feed(&[]).unwrap(), None);
    }

    #[test]
    fn parser_skips_unknown_capsule_exceeding_max_length() {
        // Build an unknown capsule whose declared length exceeds the default max
        // length without using Capsule::new, which rejects such values.
        // Unknown capsules are skipped regardless of length, without allocating
        // a Capsule value vector.
        let huge_len = DEFAULT_MAX_CAPSULE_LENGTH + 1;
        let mut encoded = quic_varint::encode(0x01); // unknown type, 1-byte varint
        encoded.extend_from_slice(&quic_varint::encode(huge_len as u64));
        encoded.resize(encoded.len() + huge_len, 0x00);

        let mut parser = CapsuleParser::new();
        assert_eq!(parser.feed(&encoded).unwrap(), None);
        assert_eq!(parser.feed(&[]).unwrap(), None);
        assert!(parser.finalize().is_ok());
    }

    #[test]
    fn parser_discards_unknown_capsule_value_incrementally() {
        // Unknown type 0x01 with a 10-byte value, fed one byte at a time.
        // The parser must not require the whole value to be buffered before
        // discarding it.
        let mut encoded = quic_varint::encode(0x01);
        encoded.extend_from_slice(&quic_varint::encode(10));
        encoded.resize(encoded.len() + 10, 0x00);

        let mut parser = CapsuleParser::new();
        for i in 0..encoded.len() {
            assert_eq!(
                parser.feed(&encoded[i..i + 1]).unwrap(),
                None,
                "should not yield a capsule at byte {i}"
            );
        }
        assert_eq!(parser.feed(&[]).unwrap(), None);
        assert!(parser.finalize().is_ok());
    }

    #[test]
    fn parser_yields_known_capsule_after_incremental_unknown_skip() {
        let unknown = Capsule::new(CapsuleType::new(0x01).unwrap(), vec![0u8; 7]).unwrap();
        let known = Capsule::new(CapsuleType::DATAGRAM, vec![0xab]).unwrap();

        let mut encoded = unknown.encode().unwrap();
        encoded.extend_from_slice(&known.encode().unwrap());

        let mut parser = CapsuleParser::new();
        let mut yielded = None;
        for chunk in encoded.chunks(3) {
            if let Some(capsule) = parser.feed(chunk).unwrap() {
                yielded = Some(capsule);
                break;
            }
        }
        assert_eq!(yielded, Some(known));
    }

    #[test]
    fn finalize_rejects_partial_unknown_capsule_value() {
        let mut parser = CapsuleParser::new();
        // Unknown type 0x01, length 10, only 3 value bytes.
        let mut encoded = quic_varint::encode(0x01);
        encoded.extend_from_slice(&quic_varint::encode(10));
        encoded.extend_from_slice(&[0x00, 0x00, 0x00]);

        assert_eq!(parser.feed(&encoded).unwrap(), None);
        let err = parser.finalize().unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramError {
                kind: H3DatagramErrorKind::Truncated,
                ..
            }
        ));
    }
}
