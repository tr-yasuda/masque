//! Integration tests for the generic Capsule Protocol parser stream (RFC 9297
//! Section 3.2).

use masque::capsule::DEFAULT_MAX_CAPSULE_LENGTH;
use masque::{Capsule, CapsuleParser, CapsuleType, Error, H3DatagramErrorKind};

mod common;
use common::{FEED_CHUNK_SIZE, UNKNOWN_CAPSULE_TYPE, encode_capsule_stream, parse_known_capsules};

#[test]
fn empty_capsule_stream_finalizes_cleanly() {
    assert!(parse_known_capsules(&[]).is_ok());
}

#[test]
fn capsule_stream_round_trips_mixed_known_and_unknown_capsules() {
    let known_a = Capsule::new(CapsuleType::DATAGRAM, vec![0x01, 0x02]).unwrap();
    let unknown = Capsule::new(
        CapsuleType::new(UNKNOWN_CAPSULE_TYPE).unwrap(),
        vec![0xab, 0xcd],
    )
    .unwrap();
    let known_b = Capsule::new(CapsuleType::DATAGRAM, vec![0x03, 0x04, 0x05]).unwrap();

    let encoded = encode_capsule_stream(&[known_a.clone(), unknown, known_b.clone()]);
    let parsed = parse_known_capsules(&encoded).unwrap();

    assert_eq!(parsed, vec![known_a, known_b]);
}

#[test]
fn capsule_stream_preserves_order_across_many_capsules() {
    let capsules: Vec<Capsule> = (0..10)
        .map(|i| Capsule::new(CapsuleType::DATAGRAM, vec![i]).unwrap())
        .collect();

    let encoded = encode_capsule_stream(&capsules);
    let parsed = parse_known_capsules(&encoded).unwrap();

    assert_eq!(parsed, capsules);
}

#[test]
fn capsule_stream_round_trips_varint_length_boundaries() {
    for len in [63usize, 64, 16_383, 16_384] {
        let capsule = Capsule::new(CapsuleType::DATAGRAM, vec![0u8; len]).unwrap();
        let encoded = encode_capsule_stream(std::slice::from_ref(&capsule));
        let parsed = parse_known_capsules(&encoded).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0], capsule);
    }
}

#[test]
fn capsule_stream_rejects_truncated_type_varint() {
    let mut parser = CapsuleParser::new();
    // 0xc0 starts an 8-byte type varint; only the first byte is supplied.
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
fn capsule_stream_rejects_truncated_length_varint() {
    let mut parser = CapsuleParser::new();
    // Type = DATAGRAM, then 0x80 starts a 4-byte length varint with only one
    // continuation byte supplied.
    assert_eq!(parser.feed(&[0x00, 0x80]).unwrap(), None);

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
fn capsule_stream_rejects_truncated_known_value() {
    let mut parser = CapsuleParser::new();
    // DATAGRAM capsule type (0x00), length 0x05, but only two value bytes.
    parser.feed(&[0x00, 0x05, 0x01, 0x02]).unwrap();

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
fn capsule_stream_rejects_truncated_unknown_value() {
    let mut parser = CapsuleParser::new();
    // Unknown type, length 10, only three value bytes.
    let mut header = masque::quic_varint::encode(UNKNOWN_CAPSULE_TYPE);
    header.extend_from_slice(&masque::quic_varint::encode(10));
    header.extend_from_slice(&[0x00, 0x00, 0x00]);
    parser.feed(&header).unwrap();

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
fn capsule_stream_accepts_length_at_default_max() {
    let payload = vec![0x55; DEFAULT_MAX_CAPSULE_LENGTH];
    let capsule = Capsule::new(CapsuleType::DATAGRAM, payload).unwrap();
    let encoded = encode_capsule_stream(&[capsule]);

    let parsed = parse_known_capsules(&encoded).unwrap();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].length(), DEFAULT_MAX_CAPSULE_LENGTH as u64);
}

#[test]
fn capsule_stream_rejects_length_exceeding_default_max() {
    let payload = vec![0x55; DEFAULT_MAX_CAPSULE_LENGTH + 1];
    let capsule = Capsule::new(CapsuleType::DATAGRAM, payload).unwrap();
    let encoded = encode_capsule_stream(&[capsule]);

    let err = parse_known_capsules(&encoded).unwrap_err();
    assert!(matches!(
        err,
        Error::H3DatagramError {
            kind: H3DatagramErrorKind::LengthTooLarge,
            ..
        }
    ));
}

#[test]
fn capsule_stream_respects_custom_max_length() {
    let max_length = 64;
    let payload = vec![0x55; max_length + 1];
    let capsule = Capsule::new(CapsuleType::DATAGRAM, payload).unwrap();
    let encoded = encode_capsule_stream(&[capsule]);

    let mut parser = CapsuleParser::with_max_length(max_length);
    let mut parse_err = None;
    for chunk in encoded.chunks(FEED_CHUNK_SIZE) {
        match parser.feed(chunk) {
            Ok(Some(capsule)) => {
                panic!("oversized capsule should not be yielded, got {capsule:?}");
            }
            Ok(None) => {}
            Err(e) => {
                parse_err = Some(e);
                break;
            }
        }
    }

    let err = parse_err.expect("expected LengthTooLarge error while parsing");
    assert!(matches!(
        err,
        Error::H3DatagramError {
            kind: H3DatagramErrorKind::LengthTooLarge,
            ..
        }
    ));
}

#[test]
fn capsule_stream_yields_no_known_capsules_for_all_unknown_stream() {
    let unknown_a =
        Capsule::new(CapsuleType::new(UNKNOWN_CAPSULE_TYPE).unwrap(), vec![0x01]).unwrap();
    let unknown_b = Capsule::new(
        CapsuleType::new(UNKNOWN_CAPSULE_TYPE + 1).unwrap(),
        vec![0x02],
    )
    .unwrap();

    let encoded = encode_capsule_stream(&[unknown_a, unknown_b]);
    let parsed = parse_known_capsules(&encoded).unwrap();

    assert!(parsed.is_empty());
}

#[test]
fn capsule_stream_accepts_exactly_custom_max_length() {
    let max_length = 64;
    let payload = vec![0x55; max_length];
    let capsule = Capsule::new(CapsuleType::DATAGRAM, payload).unwrap();
    let encoded = encode_capsule_stream(std::slice::from_ref(&capsule));

    let mut parser = CapsuleParser::with_max_length(max_length);
    let mut parsed = Vec::new();
    for chunk in encoded.chunks(FEED_CHUNK_SIZE) {
        if let Some(capsule) = parser.feed(chunk).unwrap() {
            parsed.push(capsule);
        }
        while let Some(capsule) = parser.next_capsule().unwrap() {
            parsed.push(capsule);
        }
    }

    assert_eq!(parsed, vec![capsule]);
}
