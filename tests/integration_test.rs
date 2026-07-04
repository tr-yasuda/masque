//! Integration tests for the `masque` crate.

use masque::{Config, Protocol, Session};

#[test]
fn config_round_trip() {
    let config = Config::new("0.0.0.0:0", "127.0.0.1:443").unwrap();
    assert_eq!(config.bind_addr, "0.0.0.0:0");
    assert_eq!(config.peer_addr, "127.0.0.1:443");
}

#[test]
fn session_holds_protocol() {
    let session = Session::new(Protocol::ConnectUdp);
    assert_eq!(session.protocol(), Protocol::ConnectUdp);
}

#[test]
fn not_implemented_error_can_be_created() {
    let err = masque::Error::NotImplemented {
        message: "CONNECT-UDP proxy".into(),
    };
    assert!(err.to_string().contains("CONNECT-UDP proxy"));
}
