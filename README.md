# masque

A Rust workspace for learning, implementing, and validating MASQUE-related RFCs and Internet-Drafts.

## Project goal

The primary goal of this repository is to provide a small, idiomatic Rust scaffold for reading MASQUE specifications and prototyping implementations. We start with a minimal foundation so that a CONNECT-UDP proof-of-concept can be built incrementally without committing to a full protocol stack from day one.

The long-term vision is to grow the `masque` crate into a reusable library for MASQUE clients and proxies.

## Implemented / planned specifications

| Document | Status | Notes |
|----------|--------|-------|
| [RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000) QUIC | planned | Transport foundation; we will use an existing crate. |
| [RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114) HTTP/3 | planned | Used for CONNECT method semantics over QUIC. |
| [RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297) HTTP Datagrams | planned | Required for tunneling UDP payloads in HTTP/3. |
| [RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298) CONNECT-UDP | in progress | Initial focus; stub example exists. |
| CONNECT-IP draft | planned | Future work after CONNECT-UDP. |
| CONNECT-Ethernet draft | planned | Future work after CONNECT-IP. |

## Current scope

- A `masque` core library crate containing types, errors, and configuration primitives.
- Plain UDP echo client/server examples for local testing.
- A `connect_udp_proxy.rs` example stub with TODOs for the MASQUE-specific logic.
- A minimal `xtask` helper to run fmt, clippy, doc, and tests.
- GitHub Actions CI that runs the same quality checks.

## Non-goals

- A from-scratch QUIC or HTTP/3 implementation.
- Production-ready proxy deployment in the initial phase.
- Full CONNECT-IP / CONNECT-Ethernet support before CONNECT-UDP is demonstrated.
- Performance optimization before correctness and spec coverage.

## Implementation approach

We intentionally avoid writing QUIC and HTTP/3 from scratch. Instead, the project will be built on top of established Rust crates. Candidate dependencies under evaluation include:

- [`quinn`](https://crates.io/crates/quinn) — async QUIC built on `rustls` and `tokio`.
- [`h3`](https://crates.io/crates/h3) / [`h3-quinn`](https://crates.io/crates/h3-quinn) — HTTP/3 client/server over Quinn.
- [`rustls`](https://crates.io/crates/rustls) — TLS 1.3 for QUIC handshakes.
- [`tokio`](https://crates.io/crates/tokio) — async runtime for examples and proxy demos.

No HTTP/3 or QUIC dependencies are included yet; the first step is to stabilize the core types and example structure.

## Development commands

```bash
# Run all workspace tests
cargo test --workspace

# Check formatting
cargo fmt --all -- --check

# Run clippy with warnings as errors
cargo clippy --workspace --all-targets -- -D warnings

# Check documentation
cargo doc --workspace --no-deps --document-private-items

# Run the development helper (fmt + clippy + doc + test)
cargo xtask ci
```

## Running examples

```bash
# UDP echo server
cargo run --package masque --example udp_echo_server -- 127.0.0.1:3456

# UDP echo client
cargo run --package masque --example udp_echo_client -- 127.0.0.1:3456 "hello"

# CONNECT-UDP proxy stub
cargo run --package masque --example connect_udp_proxy -- 0.0.0.0:8443 127.0.0.1:53
```

## Roadmap

1. **Scaffold** (current)
   - Workspace layout, core crate, examples, tests, CI.
2. **CONNECT-UDP PoC**
   - Add HTTP/3 dependencies, implement CONNECT-UDP request handling, and map HTTP Datagrams to UDP.
3. **Validation**
   - Add integration tests against a local HTTP/3 server and capture spec edge cases.
4. **CONNECT-IP / CONNECT-Ethernet**
   - Extend the library to additional MASQUE protocols.
5. **API stabilization**
   - Refine public API, add documentation, and publish an early `masque` crate.

## License

This project is licensed under either of the following, at your option:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))
