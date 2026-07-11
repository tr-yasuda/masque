//! Integration tests for the `masque` crate.
//!
//! These tests exercise the public API surface from outside the crate and
//! verify the runtime behavior of the included examples.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use masque::quic_varint::{self, MAX_VARINT};
use masque::{
    CAPSULE_PROTOCOL, CONNECT_UDP_PROTOCOL, Capsule, CapsuleParser, CapsuleProtocolError,
    CapsuleType, Config, ConnectUdpRequest, DatagramCapsule, DatagramPayload, Error,
    H3DatagramErrorKind, H3DatagramSettingValue, HttpDatagram, Protocol, SETTINGS_H3_DATAGRAM,
    Session, VarIntErrorKind, parse_capsule_protocol, serialize_capsule_protocol,
    validate_h3_datagram_setting_value,
};

/// RAII guard that kills a spawned child process when dropped.
struct KillOnDrop(Child);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Resolve the Cargo target directory for this workspace.
///
/// Honors `CARGO_TARGET_DIR` when set, otherwise falls back to the default
/// `target` directory at the workspace root.
fn target_dir() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.join("../..");

    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(target_dir) => {
            let target_dir = PathBuf::from(target_dir);
            if target_dir.is_absolute() {
                target_dir
            } else {
                // Cargo resolves relative CARGO_TARGET_DIR against the current
                // working directory. The test builds from the crate manifest
                // directory, so resolve relative to that.
                manifest_dir.join(target_dir)
            }
        }
        None => workspace_root.join("target"),
    }
}

#[test]
fn config_parses_and_exposes_socket_addresses() {
    let config = Config::new("0.0.0.0:0", "127.0.0.1:443").unwrap();
    assert_eq!(
        config.bind_addr(),
        "0.0.0.0:0".parse::<SocketAddr>().unwrap()
    );
    assert_eq!(config.peer_addr(), "127.0.0.1:443".parse().unwrap());
}

#[test]
fn config_rejects_invalid_peer_address() {
    let err = Config::new("0.0.0.0:0", "not-an-address").unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidConfig {
            field: "peer_addr",
            ..
        }
    ));
    let text = err.to_string();
    assert!(text.contains("peer_addr"));
    assert!(text.contains("not a valid socket address"));
}

#[test]
fn config_rejects_hostname() {
    let err = Config::new("example.com:443", "127.0.0.1:53").unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidConfig {
            field: "bind_addr",
            ..
        }
    ));
    assert!(err.to_string().contains("not a valid socket address"));
}

#[test]
fn session_can_be_created_for_any_protocol() {
    for protocol in [
        Protocol::ConnectUdp,
        Protocol::ConnectIp,
        Protocol::ConnectEthernet,
    ] {
        let session = Session::new(protocol);
        assert_eq!(session.protocol(), protocol);
    }
}

#[test]
fn not_implemented_error_can_be_created() {
    let err = Error::NotImplemented {
        message: "CONNECT-UDP proxy".into(),
    };
    assert!(err.to_string().contains("CONNECT-UDP proxy"));
}

#[test]
fn h3_datagram_error_can_be_created() {
    // Note: Error::H3DatagramError can only be constructed inside the crate,
    // so this integration test only verifies the Display text via an error
    // produced by the public API.
    let err = HttpDatagram::new(1, b"hello").unwrap_err();
    assert_eq!(
        err.to_string(),
        "HTTP/3 datagram or capsule protocol error (0x33): stream ID is not a client-initiated bidirectional stream ID"
    );
}

#[test]
fn error_variants_are_cloneable() {
    let variants = [
        Error::InvalidConfig {
            field: "bind_addr",
            message: "must not be empty".into(),
        },
        Error::NotImplemented {
            message: "CONNECT-UDP proxy".into(),
        },
        Error::H3DatagramSetting {
            setting: 0x33,
            value: 2,
        },
        Error::H3SettingsConflict {
            setting: 0x33,
            previous: 1,
            received: 0,
        },
        // H3DatagramError is omitted here because its message can only be
        // constructed inside the crate; clone/equality is covered by unit tests.
    ];
    for err in variants {
        let cloned = err.clone();
        assert_eq!(err, cloned);
        assert_eq!(err.to_string(), cloned.to_string());
    }
}

#[test]
fn settings_h3_datagram_constant_matches_rfc9297() {
    assert_eq!(SETTINGS_H3_DATAGRAM, 0x33);
}

#[test]
fn h3_datagram_setting_value_newtype_works() {
    let enabled = H3DatagramSettingValue::new(1).unwrap();
    assert!(enabled.is_enabled());
    assert_eq!(enabled.get(), 1);
    assert_eq!(enabled, H3DatagramSettingValue::ENABLED);

    let disabled = H3DatagramSettingValue::new(0).unwrap();
    assert!(!disabled.is_enabled());
    assert_eq!(disabled.get(), 0);
    assert_eq!(disabled, H3DatagramSettingValue::DISABLED);

    let err = H3DatagramSettingValue::new(2).unwrap_err();
    assert!(matches!(
        err,
        Error::H3DatagramSetting {
            setting: 0x33,
            value: 2,
        }
    ));
    assert_eq!(
        err.to_string(),
        "invalid HTTP/3 datagram setting 0x33: value must be 0 or 1, got 2"
    );
}

#[test]
fn validate_h3_datagram_setting_value_accepts_valid_values() {
    assert!(validate_h3_datagram_setting_value(0).is_ok());
    assert!(validate_h3_datagram_setting_value(1).is_ok());
}

#[test]
fn validate_h3_datagram_setting_value_rejects_invalid_values() {
    let err = validate_h3_datagram_setting_value(2).unwrap_err();
    assert!(matches!(
        err,
        Error::H3DatagramSetting {
            setting: 0x33,
            value: 2,
        }
    ));
    assert_eq!(
        err.to_string(),
        "invalid HTTP/3 datagram setting 0x33: value must be 0 or 1, got 2"
    );
}

#[test]
fn session_reports_h3_datagram_enabled_only_when_both_sides_agree() {
    let mut session = Session::new(Protocol::ConnectUdp);
    assert!(!session.is_h3_datagram_enabled());

    session
        .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
        .unwrap();
    assert!(!session.is_h3_datagram_enabled());

    session
        .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
        .unwrap();
    assert!(session.is_h3_datagram_enabled());
}

#[test]
fn session_rejects_conflicting_peer_h3_datagram_renegotiation() {
    let mut session = Session::new(Protocol::ConnectUdp);
    session
        .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
        .unwrap();
    let err = session
        .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
        .unwrap_err();
    assert!(matches!(
        err,
        Error::H3SettingsConflict {
            setting: 0x33,
            previous: 1,
            received: 0,
        }
    ));
    assert_eq!(
        err.to_string(),
        "HTTP/3 setting 0x33 already negotiated with value 1; received conflicting value 0"
    );
}

#[test]
fn session_rejects_conflicting_local_h3_datagram_renegotiation() {
    let mut session = Session::new(Protocol::ConnectUdp);
    session
        .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
        .unwrap();
    let err = session
        .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
        .unwrap_err();
    assert!(matches!(
        err,
        Error::H3SettingsConflict {
            setting: 0x33,
            previous: 1,
            received: 0,
        }
    ));
}

#[test]
fn session_rejects_duplicate_peer_h3_datagram_value() {
    let mut session = Session::new(Protocol::ConnectUdp);
    session
        .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
        .unwrap();
    let err = session
        .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
        .unwrap_err();
    assert!(matches!(
        err,
        Error::H3SettingsConflict {
            setting: 0x33,
            previous: 1,
            received: 1,
        }
    ));
}

#[test]
fn session_rejects_duplicate_local_h3_datagram_value() {
    let mut session = Session::new(Protocol::ConnectUdp);
    session
        .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
        .unwrap();
    let err = session
        .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
        .unwrap_err();
    assert!(matches!(
        err,
        Error::H3SettingsConflict {
            setting: 0x33,
            previous: 0,
            received: 0,
        }
    ));
}

#[test]
fn invalid_var_int_error_can_be_created() {
    let err = Error::InvalidVarInt {
        kind: VarIntErrorKind::BufferTooShort,
        message: "buffer too short".into(),
    };
    assert!(err.to_string().contains("buffer too short"));
}

#[test]
fn quic_varint_round_trips_boundary_values() {
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
        let encoded = quic_varint::encode(value);
        let (decoded, consumed) = quic_varint::decode(&encoded).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(consumed, encoded.len());
    }
}

#[test]
fn quic_varint_decode_rejects_invalid_input() {
    let err = quic_varint::decode(&[]).unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidVarInt {
            kind: VarIntErrorKind::EmptyBuffer,
            ..
        }
    ));

    let err = quic_varint::decode(&[0x40]).unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidVarInt {
            kind: VarIntErrorKind::BufferTooShort,
            ..
        }
    ));
}

#[test]
fn quic_varint_decode_accepts_overlong_encodings() {
    // RFC 9000 Section 16 allows overlong encodings except for Frame Type.
    assert_eq!(quic_varint::decode(&[0x40, 0x05]).unwrap(), (5, 2));
    assert_eq!(
        quic_varint::decode(&[0x80, 0x00, 0x00, 0x05]).unwrap(),
        (5, 4)
    );
    assert_eq!(
        quic_varint::decode(&[0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05]).unwrap(),
        (5, 8)
    );
}

#[test]
fn quic_varint_try_encode_rejects_oversized_values() {
    let err = quic_varint::try_encode(MAX_VARINT + 1).unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidVarInt {
            kind: VarIntErrorKind::ValueTooLarge,
            ..
        }
    ));
}

#[test]
fn quic_varint_encode_into_writes_to_caller_buffer() {
    let mut buf = [0u8; 8];
    let n = quic_varint::encode_into(64, &mut buf).unwrap();
    assert_eq!(n, 2);
    assert_eq!(&buf[..n], &[0x40, 0x40]);
}

#[test]
fn quic_varint_decode_at_reads_from_offset() {
    let buf = &[0x00, 0x40, 0x40, 0xff];
    let (value, consumed) = quic_varint::decode_at(buf, 1).unwrap();
    assert_eq!(value, 64);
    assert_eq!(consumed, 2);
}

#[test]
fn max_varint_is_publicly_accessible() {
    assert_eq!(MAX_VARINT, 4_611_686_018_427_387_903);
}

#[test]
fn http_datagram_can_be_constructed_with_valid_stream_id() {
    let datagram = HttpDatagram::new(0, b"hello").unwrap();
    assert_eq!(datagram.stream_id(), 0);
    assert_eq!(datagram.payload(), b"hello");
}

#[test]
fn http_datagram_rejects_invalid_stream_id() {
    let err = HttpDatagram::new(1, b"hello").unwrap_err();
    assert!(matches!(err, Error::H3DatagramError { .. }));
}

#[test]
fn http_datagram_round_trips_payload_through_parts() {
    let payload = vec![1, 2, 3];
    let datagram = HttpDatagram::new(4, payload.clone()).unwrap();
    let (stream_id, got_payload) = datagram.into_parts();
    assert_eq!(stream_id, 4);
    assert_eq!(got_payload, payload);
}

/// A simple payload type used to exercise the public [`DatagramPayload`] trait.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TestPayload(Vec<u8>);

impl DatagramPayload for TestPayload {
    type Error = Error;

    fn encode(&self) -> std::result::Result<Vec<u8>, Self::Error> {
        Ok(self.0.clone())
    }

    fn decode(payload: &[u8]) -> std::result::Result<Self, Self::Error> {
        Ok(Self(payload.to_vec()))
    }
}

#[test]
fn datagram_payload_trait_round_trips_through_public_api() {
    let original = TestPayload(vec![1, 2, 3]);
    let encoded = original.encode().unwrap();
    let decoded = TestPayload::decode(&encoded).unwrap();
    assert_eq!(original, decoded);
}

#[test]
fn capsule_protocol_header_name_is_accessible_at_crate_root() {
    assert_eq!(CAPSULE_PROTOCOL, "capsule-protocol");
}

#[test]
fn capsule_protocol_parses_and_serializes_at_crate_root() {
    assert_eq!(parse_capsule_protocol("?1"), Ok(true));
    assert_eq!(parse_capsule_protocol("?0"), Ok(false));
    assert_eq!(parse_capsule_protocol(" ?1;foo=bar "), Ok(true));
    assert_eq!(
        parse_capsule_protocol("true"),
        Err(CapsuleProtocolError::NotBoolean)
    );

    for value in [true, false] {
        assert_eq!(
            parse_capsule_protocol(serialize_capsule_protocol(value)),
            Ok(value)
        );
    }
}

#[test]
fn capsule_type_datagram_value_is_zero_from_public_api() {
    assert_eq!(CapsuleType::DATAGRAM.value(), 0);
    assert!(CapsuleType::DATAGRAM.is_datagram());
    assert!(!CapsuleType::DATAGRAM.is_unknown());
    assert_eq!(CapsuleType::new(0).unwrap(), CapsuleType::DATAGRAM);
}

#[test]
fn capsule_type_rejects_out_of_range_value_from_public_api() {
    use masque::quic_varint::MAX_VARINT;
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
fn capsule_round_trips_known_and_unknown_types_from_public_api() {
    let known = Capsule::new(CapsuleType::DATAGRAM, vec![0x01, 0x02]).unwrap();
    let encoded = known.encode().unwrap();
    let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.capsule_type(), CapsuleType::DATAGRAM);
    assert_eq!(decoded.value(), &[0x01, 0x02]);

    let unknown = Capsule::new(CapsuleType::new(0x2bad).unwrap(), vec![0xab]).unwrap();
    let encoded = unknown.encode().unwrap();
    let (decoded, consumed) = Capsule::decode(&encoded).unwrap();
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.capsule_type().value(), 0x2bad);
    assert!(decoded.capsule_type().is_unknown());
}

#[test]
fn capsule_decode_rejects_truncated_value_from_public_api() {
    let encoded = [0x00, 0x05, 0x01, 0x02];
    let err = Capsule::decode(&encoded).unwrap_err();
    assert!(matches!(
        err,
        Error::H3DatagramError {
            kind: H3DatagramErrorKind::Truncated,
            ..
        }
    ));
}

#[test]
fn capsule_decode_wraps_invalid_varint_header_in_h3_datagram_error_from_public_api() {
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
fn capsule_parser_skips_unknown_types_and_yields_known_types() {
    let datagram = Capsule::new(CapsuleType::DATAGRAM, vec![0xde, 0xad]).unwrap();
    let unknown = Capsule::new(CapsuleType::new(0x2bad).unwrap(), vec![0xbe, 0xef]).unwrap();

    let mut encoded = datagram.encode().unwrap();
    encoded.extend_from_slice(&unknown.encode().unwrap());

    let mut parser = CapsuleParser::new();
    assert_eq!(parser.feed(&encoded).unwrap(), Some(datagram));
    assert_eq!(parser.feed(&[]).unwrap(), None);
}

#[test]
fn capsule_parser_handles_partial_input() {
    let mut parser = CapsuleParser::new();
    assert_eq!(parser.feed(&[0x00]).unwrap(), None);
    assert_eq!(parser.feed(&[0x02]).unwrap(), None);
    assert_eq!(parser.feed(&[0x01]).unwrap(), None);
    let capsule = parser.feed(&[0x02]).unwrap().unwrap();
    assert_eq!(capsule.capsule_type(), CapsuleType::DATAGRAM);
    assert_eq!(capsule.value(), &[0x01, 0x02]);
    assert_eq!(parser.feed(&[]).unwrap(), None);
}

#[test]
fn udp_echo_server_example_echoes_datagrams() {
    // Build the example binary so we can run it directly (avoiding the cargo
    // wrapper, which makes process cleanup easier).
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let build_status = Command::new("cargo")
        .current_dir(manifest_dir)
        .args(["build", "--example", "udp_echo_server"])
        .status()
        .expect("cargo should be available");
    assert!(build_status.success(), "failed to build udp_echo_server");

    let exe = target_dir()
        .join("debug/examples/udp_echo_server")
        .with_extension(if cfg!(windows) { "exe" } else { "" });

    // Wrap the Child in a guard immediately after spawning so it is killed even
    // if an assertion panics before we finish reading stdout.
    let mut server = KillOnDrop(
        Command::new(&exe)
            .arg("127.0.0.1:0")
            .stdout(Stdio::piped())
            .spawn()
            .expect("failed to spawn udp_echo_server"),
    );

    let stdout = server.0.stdout.take().expect("server stdout not captured");
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout).lines();
        tx.send(reader.next().transpose())
            .expect("failed to send server output");
    });

    let first_line = rx
        .recv_timeout(Duration::from_secs(10))
        .expect("server did not produce output within timeout")
        .expect("failed to read server output")
        .expect("server produced no output");

    // Parse "UDP echo server listening on 127.0.0.1:PORT"
    let addr: SocketAddr = first_line
        .rsplit_once(' ')
        .and_then(|(_, addr)| addr.parse().ok())
        .expect("could not parse server listen address");

    let client = UdpSocket::bind("127.0.0.1:0").expect("failed to bind client");
    client.connect(addr).expect("failed to connect client");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();

    // UDP is lossy even on loopback; retry a few times before giving up.
    let mut buf = [0u8; 1024];
    let mut echoed = false;
    for attempt in 0..3 {
        client.send(b"hello").expect("failed to send");
        match client.recv(&mut buf) {
            Ok(n) => {
                assert_eq!(&buf[..n], b"hello");
                echoed = true;
                break;
            }
            Err(e) if attempt < 2 => {
                eprintln!("Echo attempt {attempt} failed: {e}; retrying...");
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => panic!("failed to receive echo within timeout: {e}"),
        }
    }
    assert!(echoed, "server did not echo the datagram");

    // Explicit cleanup is still good practice, but the Drop guard above ensures
    // the process is terminated even if a panic unwinds past this point.
    let _ = server.0.kill();
    let _ = server.0.wait();
}

#[test]
fn datagram_capsule_round_trips_from_public_api() {
    let datagram = HttpDatagram::new(12, vec![1, 2, 3]).unwrap();
    let capsule = DatagramCapsule::new(datagram);
    let encoded = capsule.encode().unwrap();
    let (decoded, consumed) = DatagramCapsule::decode(&encoded, 12).unwrap();
    assert_eq!(consumed, encoded.len());
    assert_eq!(decoded.datagram().stream_id(), 12);
    assert_eq!(decoded.datagram().payload(), &[1, 2, 3]);
}

#[test]
fn datagram_capsule_rejects_truncated_value_from_public_api() {
    let encoded = [0x00, 0x05, 0x01, 0x02];
    let err = DatagramCapsule::decode(&encoded, 0).unwrap_err();
    assert!(matches!(
        err,
        Error::H3DatagramError {
            kind: H3DatagramErrorKind::Truncated,
            ..
        }
    ));
}

#[test]
fn connect_udp_request_exposes_public_api() {
    let req = ConnectUdpRequest::new("target.example", 53, Some("cfg")).unwrap();
    assert_eq!(req.target_host(), "target.example");
    assert_eq!(req.target_port(), 53);
    assert_eq!(req.udp_proxy_config(), Some("cfg"));
}

#[test]
fn connect_udp_protocol_constant_is_accessible_at_crate_root() {
    assert_eq!(CONNECT_UDP_PROTOCOL, "connect-udp");
}

#[test]
fn connect_udp_request_rejects_invalid_port_from_public_api() {
    let err = ConnectUdpRequest::new("target.example", 0, None::<String>).unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidConnectUdpRequest {
            field: "target_port",
            ..
        }
    ));
}

#[test]
fn connect_udp_request_rejects_missing_target_host_from_public_api() {
    let err =
        ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_port=53").unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidConnectUdpRequest {
            field: "target_host",
            ..
        }
    ));
}

#[test]
fn connect_udp_request_uri_generation_rejects_invalid_proxy_authority_from_public_api() {
    let req = ConnectUdpRequest::new("target.example", 53, None::<String>).unwrap();
    let err = req.to_uri("proxy.example:443/evil").unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidConnectUdpRequest {
            field: "proxy_authority",
            ..
        }
    ));
}

#[test]
fn udp_carrier_variants_are_publicly_accessible() {
    assert_eq!(
        masque::UdpCarrier::H3Datagram,
        masque::UdpCarrier::H3Datagram
    );
    assert_eq!(
        masque::UdpCarrier::DatagramCapsule,
        masque::UdpCarrier::DatagramCapsule
    );
    assert_ne!(
        masque::UdpCarrier::H3Datagram,
        masque::UdpCarrier::DatagramCapsule
    );
}

#[test]
fn session_selects_udp_carrier_from_public_api() {
    use masque::{H3DatagramSettingValue, Protocol, Session, UdpCarrier};

    let mut session = Session::new(Protocol::ConnectUdp);
    session
        .set_local_h3_datagram(H3DatagramSettingValue::ENABLED)
        .unwrap();
    session
        .negotiate_peer_h3_datagram(H3DatagramSettingValue::ENABLED)
        .unwrap();
    assert_eq!(
        session.select_udp_carrier().unwrap(),
        UdpCarrier::H3Datagram
    );
}

#[test]
fn session_selects_datagram_capsule_carrier_from_public_api() {
    use masque::{H3DatagramSettingValue, Protocol, Session, UdpCarrier};

    let mut session = Session::new(Protocol::ConnectUdp);
    session
        .set_local_h3_datagram(H3DatagramSettingValue::DISABLED)
        .unwrap();
    session
        .negotiate_peer_h3_datagram(H3DatagramSettingValue::DISABLED)
        .unwrap();
    session.set_local_capsule_protocol(true).unwrap();
    session.negotiate_peer_capsule_protocol(true).unwrap();
    assert_eq!(
        session.select_udp_carrier().unwrap(),
        UdpCarrier::DatagramCapsule
    );
}
