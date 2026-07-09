//! Integration tests for the HTTP/3 client/server scaffold.

#![cfg(all(feature = "h3", feature = "test-utils"))]

use std::net::SocketAddr;
use std::time::Duration;

use masque::{
    Error, H3_ALPN, H3Client, H3Server, dangerous_test_client_config, generate_self_signed_cert,
};

const TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn h3_client_sends_request_and_receives_200() {
    let (certs, key) = generate_self_signed_cert(&["localhost"]).unwrap();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tls_config.alpn_protocols = vec![H3_ALPN[..].into()];

    let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap(),
    ));

    let mut server =
        H3Server::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), server_config).unwrap();
    let server_addr = server.local_addr().unwrap();

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();

    let server_task = tokio::spawn(async move {
        let mut conn = tokio::time::timeout(TIMEOUT, server.accept())
            .await
            .unwrap()
            .unwrap()
            .expect("expected a connection");
        assert_eq!(
            conn.remote_addr().ip(),
            std::net::IpAddr::V4("127.0.0.1".parse().unwrap())
        );
        let resolver = tokio::time::timeout(TIMEOUT, conn.accept_request())
            .await
            .unwrap()
            .unwrap()
            .expect("expected a request");
        let (_req, mut stream) = resolver.resolve_request().await.unwrap();
        let response = http::Response::builder().status(200).body(()).unwrap();
        stream.send_response(response).await.unwrap();
        stream.finish().await.unwrap();
        let _ = shutdown_rx.await;
        // Keep the connection alive so the client observes a local H3_NO_ERROR
        // close rather than a remote QUIC error when it shuts down.
        std::future::pending::<()>().await;
    });

    let client_config = dangerous_test_client_config().unwrap();
    let client = tokio::time::timeout(
        TIMEOUT,
        H3Client::connect(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            server_addr,
            "localhost",
            client_config,
        ),
    )
    .await
    .unwrap()
    .unwrap();

    let request = http::Request::builder()
        .uri("https://localhost/")
        .body(())
        .unwrap();
    let mut stream = client.send_request().send_request(request).await.unwrap();
    stream.finish().await.unwrap();

    let response = tokio::time::timeout(TIMEOUT, stream.recv_response())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), 200);

    shutdown_tx.send(()).unwrap();

    // Close the client endpoint. After a graceful shutdown this must return Ok(()).
    let close_result = tokio::time::timeout(TIMEOUT, client.close()).await.unwrap();
    assert!(
        close_result.is_ok(),
        "H3Client::close() should return Ok(()) after graceful shutdown, got {:?}",
        close_result
    );

    // Abort the server task so the endpoint and connection are dropped. Keeping
    // the server connection alive until now lets the client close observe a
    // local H3_NO_ERROR instead of a remote QUIC error.
    server_task.abort();
    let _ = server_task.await;
}

#[tokio::test]
async fn h3_server_accept_returns_none_after_close() {
    let (certs, key) = generate_self_signed_cert(&["localhost"]).unwrap();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tls_config.alpn_protocols = vec![H3_ALPN[..].into()];

    let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap(),
    ));

    let mut server =
        H3Server::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), server_config).unwrap();
    server.close();

    let result = tokio::time::timeout(TIMEOUT, server.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn h3_server_close_during_accept_returns_none() {
    let (certs, key) = generate_self_signed_cert(&["localhost"]).unwrap();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tls_config.alpn_protocols = vec![H3_ALPN[..].into()];

    let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap(),
    ));

    let mut server =
        H3Server::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), server_config).unwrap();

    // Close the endpoint while no connection is in flight. Any pending accept()
    // must observe the close rather than a transport error.
    server.close();

    let result = tokio::time::timeout(TIMEOUT, server.accept())
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn h3_client_drop_without_close_does_not_hang() {
    let (certs, key) = generate_self_signed_cert(&["localhost"]).unwrap();

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    tls_config.alpn_protocols = vec![H3_ALPN[..].into()];

    let server_config = quinn::ServerConfig::with_crypto(std::sync::Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap(),
    ));

    let mut server =
        H3Server::bind("127.0.0.1:0".parse::<SocketAddr>().unwrap(), server_config).unwrap();
    let server_addr = server.local_addr().unwrap();

    // Accept the connection in the background so the client can complete its
    // handshake. The task keeps the connection alive until it observes a close.
    let server_task = tokio::spawn(async move {
        let _conn = tokio::time::timeout(TIMEOUT, server.accept())
            .await
            .unwrap()
            .unwrap()
            .expect("expected a connection");
        // Wait long enough for the client to drop and send a close frame.
        tokio::time::sleep(Duration::from_millis(200)).await;
    });

    let client_config = dangerous_test_client_config().unwrap();
    let client = tokio::time::timeout(
        TIMEOUT,
        H3Client::connect(
            "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
            server_addr,
            "localhost",
            client_config,
        ),
    )
    .await
    .unwrap()
    .unwrap();

    // Drop the client without calling close(). The Drop impl should close the
    // endpoint and abort the driver task so this does not hang.
    drop(client);

    // The server task and the subsequent accept must not hang.
    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn h3_client_connect_rejects_invalid_remote_address() {
    let client_config = dangerous_test_client_config().unwrap();

    // 0.0.0.0 is not a usable remote address, so the connection attempt should
    // fail immediately rather than hanging until a timeout fires.
    let result = H3Client::connect(
        "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        "0.0.0.0:443".parse::<SocketAddr>().unwrap(),
        "localhost",
        client_config,
    )
    .await;

    let err = result.expect_err("expected a connection error");
    assert!(
        matches!(err, Error::Transport { .. }),
        "expected Error::Transport, got {err:?}"
    );
}
