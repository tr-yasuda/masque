//! Integration tests for HTTP/3 Datagram ↔ DATAGRAM Capsule interop and
//! intermediary-style forwarding semantics (RFC 9297 Section 3.5).

use masque::quic_varint::MAX_VARINT;
use masque::{Capsule, CapsuleType, DatagramCapsule, Error, H3DatagramErrorKind, HttpDatagram};

mod common;
use common::{UNKNOWN_CAPSULE_TYPE, parse_known_capsules};

/// Decode a parsed DATAGRAM capsule using the public API path.
fn decode_datagram_capsule(capsule: Capsule, stream_id: u64) -> HttpDatagram {
    assert!(
        capsule.capsule_type().is_datagram(),
        "expected a DATAGRAM capsule"
    );
    let encoded = capsule.encode().unwrap();
    let (decoded, consumed) = DatagramCapsule::decode(&encoded, stream_id).unwrap();
    assert_eq!(consumed, encoded.len());
    decoded.into_datagram()
}

#[test]
fn h3_datagram_round_trips_through_datagram_capsule_stream() {
    let datagrams = [
        HttpDatagram::new(0, b"hello").unwrap(),
        HttpDatagram::new(4, Vec::new()).unwrap(),
        HttpDatagram::new(256, vec![0xff; 100]).unwrap(),
    ];

    for original in &datagrams {
        let capsule = DatagramCapsule::new(original.clone());
        let encoded = capsule.encode().unwrap();

        let parsed = parse_known_capsules(&encoded).unwrap();
        assert_eq!(parsed.len(), 1);

        let round_tripped =
            decode_datagram_capsule(parsed.into_iter().next().unwrap(), original.stream_id());
        assert_eq!(round_tripped.stream_id(), original.stream_id());
        assert_eq!(round_tripped.payload(), original.payload());
        assert_eq!(round_tripped.encode_h3(), original.encode_h3());
    }
}

#[test]
fn h3_datagram_round_trips_large_stream_ids() {
    let datagrams = [
        HttpDatagram::new(65_536, b"four-byte-quarter-stream-id").unwrap(),
        HttpDatagram::new(MAX_VARINT - 3, b"maximum-valid-stream-id").unwrap(),
    ];

    for original in &datagrams {
        let capsule = DatagramCapsule::new(original.clone());
        let encoded = capsule.encode().unwrap();

        let parsed = parse_known_capsules(&encoded).unwrap();
        assert_eq!(parsed.len(), 1);

        let round_tripped =
            decode_datagram_capsule(parsed.into_iter().next().unwrap(), original.stream_id());
        assert_eq!(round_tripped, *original);
    }
}

#[test]
fn datagram_capsule_round_trips_through_h3_datagram_frame() {
    let original = HttpDatagram::new(12, vec![1, 2, 3]).unwrap();
    let capsule = DatagramCapsule::new(original.clone());
    let capsule_bytes = capsule.encode().unwrap();

    let parsed = parse_known_capsules(&capsule_bytes).unwrap();
    assert_eq!(parsed.len(), 1);

    let reconstructed =
        decode_datagram_capsule(parsed.into_iter().next().unwrap(), original.stream_id());
    let h3_frame = reconstructed.encode_h3();
    let decoded = HttpDatagram::decode_h3(&h3_frame).unwrap();

    assert_eq!(decoded.stream_id(), original.stream_id());
    assert_eq!(decoded.payload(), original.payload());
}

#[test]
fn capsule_stream_round_trips_empty_datagram_capsule() {
    let original = HttpDatagram::new(0, Vec::new()).unwrap();
    let capsule = DatagramCapsule::new(original.clone());
    let encoded = capsule.encode().unwrap();

    let parsed = parse_known_capsules(&encoded).unwrap();
    assert_eq!(parsed.len(), 1);

    let reconstructed = decode_datagram_capsule(parsed.into_iter().next().unwrap(), 0);
    assert_eq!(reconstructed, original);
}

#[test]
fn capsule_stream_handles_large_datagram_capsule() {
    // A payload large enough to require a multi-byte capsule length varint.
    let payload = vec![0x55; 1_000];
    let original = HttpDatagram::new(64, payload).unwrap();
    let capsule = DatagramCapsule::new(original.clone());
    let encoded = capsule.encode().unwrap();

    let parsed = parse_known_capsules(&encoded).unwrap();
    assert_eq!(parsed.len(), 1);

    let reconstructed =
        decode_datagram_capsule(parsed.into_iter().next().unwrap(), original.stream_id());
    assert_eq!(reconstructed, original);
}

#[test]
fn intermediary_forwards_h3_datagrams_over_capsule_stream() {
    // A proxy receives HTTP/3 Datagram frames on several request streams and
    // forwards them as DATAGRAM capsules on the corresponding streams.
    let incoming = [
        HttpDatagram::new(0, b"stream-zero").unwrap(),
        HttpDatagram::new(4, b"stream-four").unwrap(),
        HttpDatagram::new(256, b"stream-256").unwrap(),
    ];

    let mut forwarded = Vec::new();
    for datagram in &incoming {
        let capsule = DatagramCapsule::new(datagram.clone());
        capsule.encode_into(&mut forwarded).unwrap();
    }

    // The receiver parses the capsule stream and reconstructs each datagram
    // using the public DatagramCapsule::decode path with the expected stream
    // identifier from the transport context.
    let parsed = parse_known_capsules(&forwarded).unwrap();
    assert_eq!(parsed.len(), incoming.len());

    for (expected, capsule) in incoming.iter().zip(parsed) {
        let reconstructed = decode_datagram_capsule(capsule, expected.stream_id());
        assert_eq!(reconstructed.stream_id(), expected.stream_id());
        assert_eq!(reconstructed.payload(), expected.payload());
        assert_eq!(reconstructed.encode_h3(), expected.encode_h3());
    }
}

#[test]
fn intermediary_forwards_capsule_stream_with_unknown_capsules_interleaved() {
    // Unknown capsules must pass through the stream; the receiver skips them
    // and still yields the known DATAGRAM capsules in order.
    let datagram_a = HttpDatagram::new(0, b"first").unwrap();
    let datagram_b = HttpDatagram::new(8, b"second").unwrap();
    let unknown_capsule = Capsule::new(
        CapsuleType::new(UNKNOWN_CAPSULE_TYPE).unwrap(),
        vec![0xbe, 0xef],
    )
    .unwrap();

    let mut stream = Vec::new();
    DatagramCapsule::new(datagram_a.clone())
        .encode_into(&mut stream)
        .unwrap();
    stream.extend_from_slice(&unknown_capsule.encode().unwrap());
    DatagramCapsule::new(datagram_b.clone())
        .encode_into(&mut stream)
        .unwrap();

    let parsed = parse_known_capsules(&stream).unwrap();
    assert_eq!(parsed.len(), 2);

    let reconstructed_a = decode_datagram_capsule(parsed[0].clone(), datagram_a.stream_id());
    let reconstructed_b = decode_datagram_capsule(parsed[1].clone(), datagram_b.stream_id());

    assert_eq!(reconstructed_a.payload(), datagram_a.payload());
    assert_eq!(reconstructed_b.payload(), datagram_b.payload());
}

#[test]
fn datagram_capsule_decode_rejects_non_datagram_type() {
    let unknown_capsule =
        Capsule::new(CapsuleType::new(UNKNOWN_CAPSULE_TYPE).unwrap(), vec![0xab]).unwrap();
    let encoded = unknown_capsule.encode().unwrap();

    let err = DatagramCapsule::decode(&encoded, 0).unwrap_err();
    assert!(matches!(
        err,
        Error::H3DatagramError {
            kind: H3DatagramErrorKind::UnexpectedCapsuleType,
            ..
        }
    ));
}

#[test]
fn datagram_capsule_decode_rejects_invalid_stream_id() {
    let datagram = HttpDatagram::new(0, b"hello").unwrap();
    let capsule = DatagramCapsule::new(datagram);
    let encoded = capsule.encode().unwrap();

    // Stream ID 1 is not a client-initiated bidirectional stream ID.
    let err = DatagramCapsule::decode(&encoded, 1).unwrap_err();
    assert!(matches!(err, Error::H3DatagramError { .. }));
    assert!(
        err.to_string()
            .contains("not a client-initiated bidirectional stream ID")
    );
}
