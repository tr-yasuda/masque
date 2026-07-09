# masque

A Rust workspace for learning, implementing, and validating MASQUE-related RFCs and Internet-Drafts.

## Project goal

The primary goal of this repository is to provide a small, idiomatic Rust scaffold for reading MASQUE specifications and prototyping implementations. We start with a minimal foundation so that a CONNECT-UDP proof-of-concept can be built incrementally without committing to a full protocol stack from day one.

The long-term vision is to grow the `masque` crate into a reusable library for MASQUE clients and proxies.

## Implemented / planned specifications

| Document | Status | Notes |
|----------|--------|-------|
| [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) QUIC | delegated | Transport foundation provided by [`quinn`]. |
| [RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114) HTTP/3 | in progress | Used for CONNECT method semantics over QUIC; optional `h3` feature adds `H3Client`/`H3Server`. |
| [RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297) HTTP Datagrams | implemented | HTTP/3 Datagrams, DATAGRAM capsules, and `Capsule-Protocol` header support. |
| [RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298) CONNECT-UDP | in progress | Initial focus; stub example exists. |
| CONNECT-IP draft | planned | Future work after CONNECT-UDP. |
| CONNECT-Ethernet draft | planned | Future work after CONNECT-IP. |

## Current scope

- A `masque` core library crate containing types, errors, configuration primitives, and RFC 9297 building blocks (HTTP/3 Datagrams, DATAGRAM capsules, and the `Capsule-Protocol` header).
- An optional `h3` Cargo feature that adds HTTP/3 transport scaffolding (`H3Client`, `H3Server`, `H3Connection`) built on [`quinn`], [`h3`], and [`h3-quinn`].
- A `test-utils` Cargo feature that exposes self-signed certificate generation and a certificate-verification-skipping client config for local testing only.
- Plain UDP echo client/server examples for local testing.
- A `connect_udp_proxy.rs` example stub with TODOs for the MASQUE-specific logic.
- A minimal `xtask` helper to run fmt, clippy, doc, and tests, including checks with the `h3` feature enabled.
- GitHub Actions CI that runs the same quality checks.

## Non-goals

- A from-scratch QUIC or HTTP/3 implementation.
- Production-ready proxy deployment in the initial phase.
- Full CONNECT-IP / CONNECT-Ethernet support before CONNECT-UDP is demonstrated.
- Performance optimization before correctness and spec coverage.

## Implementation approach

We intentionally avoid writing QUIC and HTTP/3 from scratch. Instead, the project is built on top of established Rust crates. The optional `h3` feature pulls in:

- [`quinn`](https://crates.io/crates/quinn) — async QUIC built on `rustls` and `tokio`.
- [`h3`](https://crates.io/crates/h3) / [`h3-quinn`](https://crates.io/crates/h3-quinn) — HTTP/3 client/server over Quinn.
- [`rustls`](https://crates.io/crates/rustls) — TLS 1.3 for QUIC handshakes.
- [`tokio`](https://crates.io/crates/tokio) — async runtime for examples and proxy demos.

Default builds do not include HTTP/3 or QUIC dependencies; enable the `h3` feature to use the transport scaffolding.

## Development commands

```bash
# Run all workspace tests
cargo test --workspace --locked

# Run tests with the HTTP/3 transport scaffolding
cargo test --workspace --features masque/h3,masque/test-utils --locked

# Check formatting
cargo fmt --all -- --check

# Run clippy with warnings as errors
cargo clippy --workspace --all-targets --locked -- -D warnings

# Run clippy with the HTTP/3 feature
cargo clippy --workspace --all-targets --features masque/h3,masque/test-utils --locked -- -D warnings

# Check documentation (fails on rustdoc warnings)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked

# Check documentation with the HTTP/3 feature
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --features masque/h3,masque/test-utils --locked

# Run the development helper (fmt + clippy + doc + test, with and without h3)
cargo xtask ci
```

## Running examples

```bash
# UDP echo server
cargo run --package masque --example udp_echo_server -- 127.0.0.1:3456

# UDP echo client
cargo run --package masque --example udp_echo_client -- 127.0.0.1:3456 "hello"

# CONNECT-UDP proxy stub
cargo run --package masque --example connect_udp_proxy -- 127.0.0.1:8443 127.0.0.1:53
```

## Roadmap

1. **Scaffold** (current)
   - Workspace layout, core crate, examples, tests, CI, and optional HTTP/3 transport scaffolding behind the `h3` feature.
2. **CONNECT-UDP PoC**
   - Implement CONNECT-UDP request handling and map HTTP Datagrams to UDP.
3. **Validation**
   - Add integration tests against a local HTTP/3 server and capture spec edge cases.
4. **CONNECT-IP / CONNECT-Ethernet**
   - Extend the library to additional MASQUE protocols.
5. **API stabilization**
   - Refine public API, add documentation, and publish an early `masque` crate.

## License

This project is licensed under the MIT License ([LICENSE](LICENSE)).

[quinn]: https://crates.io/crates/quinn
[h3]: https://crates.io/crates/h3
[h3-quinn]: https://crates.io/crates/h3-quinn
