//! Integration tests for the `masque` crate.
//!
//! These tests exercise the public API surface from outside the crate and
//! verify the runtime behavior of the included examples.

use std::io::{BufRead, BufReader};
use std::net::{SocketAddr, UdpSocket};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

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
fn error_can_be_cloned() {
    let err = Error::InvalidConfig {
        field: "bind_addr",
        message: "must not be empty".into(),
    };
    let cloned = err.clone();
    assert_eq!(err, cloned);
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
