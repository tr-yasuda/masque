//! Integration tests for the `masque` crate.
//!
//! These tests exercise the public API surface from outside the crate.

use std::net::SocketAddr;

use masque::{Config, Error, Protocol, Session};

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
fn error_can_be_cloned() {
    let err = Error::InvalidConfig {
        field: "bind_addr",
        message: "must not be empty".into(),
    };
    let cloned = err.clone();
    assert_eq!(err.to_string(), cloned.to_string());
}
