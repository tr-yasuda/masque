//! Integration tests for the `masque` crate.
//!
//! These tests exercise the public API surface from outside the crate and
//! verify the runtime behavior of the included examples.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

use masque::{
    Config, Error, H3DatagramSettingValue, Protocol, SETTINGS_H3_DATAGRAM, Session,
    validate_h3_datagram_setting_value,
};

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
    let err = Error::H3DatagramError {
        message: "invalid datagram length".into(),
    };
    assert_eq!(
        err.to_string(),
        "HTTP/3 datagram or capsule protocol error (0x33): invalid datagram length"
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
        Error::H3DatagramError {
            message: "parse failed".into(),
        },
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
fn udp_echo_server_example_echoes_datagrams() {
    // Build the example binary so we can run it directly (avoiding the cargo
    // wrapper, which makes process cleanup easier).
    let build_status = Command::new("cargo")
        .args(["build", "--example", "udp_echo_server"])
        .status()
        .expect("cargo should be available");
    assert!(build_status.success(), "failed to build udp_echo_server");

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let exe = Path::new(manifest_dir)
        .join("../../target/debug/examples/udp_echo_server")
        .with_extension(if cfg!(windows) { "exe" } else { "" });

    let mut server = Command::new(exe)
        .arg("127.0.0.1:0")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to spawn udp_echo_server");

    let stdout = server.stdout.take().expect("server stdout not captured");
    let mut reader = BufReader::new(stdout).lines();
    let first_line = reader
        .next()
        .expect("server produced no output")
        .expect("failed to read server output");

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

    client.send(b"hello").expect("failed to send");
    let mut buf = [0u8; 1024];
    let n = client
        .recv(&mut buf)
        .expect("failed to receive echo within timeout");
    assert_eq!(&buf[..n], b"hello");

    let _ = server.kill();
    let _ = server.wait();
}
