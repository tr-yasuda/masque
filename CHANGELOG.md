# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Optional `h3` Cargo feature adding HTTP/3 transport scaffolding: `H3Client`,
  `H3Server`, `H3Connection`, and the `H3_ALPN` constant.
- Optional `test-utils` Cargo feature exposing `generate_self_signed_cert` and
  `dangerous_test_client_config` for local testing only.
- `Error::Transport` and `Error::InvalidCertificate` variants for HTTP/3 and TLS
  failures; both variants preserve the underlying source error chain.
- CI and `xtask` checks for the `h3` feature.
- `Error::H3DatagramError` variant and `H3_DATAGRAM_ERROR_CODE` constant for RFC 9297 `H3_DATAGRAM_ERROR` (0x33).
- Initial Cargo workspace with Rust 2024 edition and resolver 3.
- `crates/masque` library crate with core types, errors, and configuration.
- `capsule_protocol` module with the `Capsule-Protocol` header constant, parser, and serializer.
- UDP echo client/server examples.
- CONNECT-UDP proxy example stub with TODOs.
- Integration test scaffold.
- `xtask` helper for running fmt, clippy, doc, and tests.
- GitHub Actions CI workflow.
- README, CONTRIBUTING, SECURITY, and `LICENSE` files.

### Changed

- `Error` enum variants are no longer feature-gated: `Transport` and
  `InvalidCertificate` are always present so the enum shape does not depend on
  Cargo feature unification.
- Store `Config` addresses as validated `SocketAddr` values with private fields and getters.
- Structure `Error::InvalidConfig` with a `field` identifier and derive `Clone` for `Error`.
- Move examples and integration tests under `crates/masque/` so Cargo discovers them.
- Pin third-party GitHub Actions to commit SHAs and add `permissions: contents: read`.
- Run `cargo doc` and use `--locked` in CI and `xtask`.
