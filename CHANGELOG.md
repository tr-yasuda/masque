# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial Cargo workspace with Rust 2024 edition and resolver 3.
- `crates/masque` library crate with core types, errors, and configuration.
- UDP echo client/server examples.
- CONNECT-UDP proxy example stub with TODOs.
- Integration test scaffold.
- `xtask` helper for running fmt, clippy, doc, and tests.
- GitHub Actions CI workflow.
- README, CONTRIBUTING, SECURITY, `LICENSE-MIT`, and `LICENSE-APACHE` files.

### Changed

- Store `Config` addresses as validated `SocketAddr` values with private fields and getters.
- Structure `Error::InvalidConfig` with a `field` identifier and derive `Clone` for `Error`.
- Move examples and integration tests under `crates/masque/` so Cargo discovers them.
- Pin third-party GitHub Actions to commit SHAs and add `permissions: contents: read`.
- Run `cargo doc` and use `--locked` in CI and `xtask`.
