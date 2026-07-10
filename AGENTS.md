# Agent Guide for `masque`

This guide is written for AI coding agents working on the `masque` repository.
It describes the project's purpose, layout, build system, conventions, and
security context. Treat it as the single source of truth for how to make safe,
coherent changes to this codebase.

## Project overview

`masque` is a Rust workspace for learning, implementing, and validating
MASQUE-related RFCs and Internet-Drafts. The immediate goal is a small,
idiomatic scaffold that can grow into a reusable library for MASQUE clients and
proxies. The first protocol target is CONNECT-UDP (RFC 9298) over HTTP/3
(RFC 9114) and HTTP Datagrams (RFC 9297), using an existing QUIC implementation
(RFC 9000) rather than writing one from scratch.

The project is intentionally in a scaffold / proof-of-concept phase. The core
library exposes configuration primitives, error types, protocol/session types,
HTTP/3 settings helpers, and RFC 9297 building blocks: HTTP/3 Datagram payload
encoding/decoding, the Capsule Protocol parser, DATAGRAM capsule encoding/decoding,
and the `Capsule-Protocol` header helper.
Examples are plain UDP echo programs and a CONNECT-UDP proxy stub.

Key facts:

- License: MIT
- Repository: https://github.com/tr-yasuda/masque
- Rust edition: 2024
- Workspace resolver: 3
- Minimum Supported Rust Version (MSRV): 1.85
- Workspace version: 0.0.1 (all crates inherit from `workspace.package`)

## Workspace layout

```text
masque/
├── Cargo.toml              # Workspace manifest; no root package
├── Cargo.lock              # Committed lockfile; CI uses --locked
├── crates/
│   └── masque/             # The main library crate
│       ├── Cargo.toml
│       ├── src/
│       │   ├── lib.rs              # Crate root; re-exports public API
│       │   ├── capsule.rs          # Capsule Protocol message parser
│       │   ├── capsule_protocol.rs # Capsule-Protocol header helper
│       │   ├── client.rs           # HTTP/3 client (requires `h3` feature)
│       │   ├── config.rs           # Config validation and parsing
│       │   ├── connect_udp.rs      # CONNECT-UDP request type and URI template
│       │   ├── datagram.rs         # HTTP/3 Datagram payload types
│       │   ├── datagram_capsule.rs # DATAGRAM capsule encoder/decoder
│       │   ├── error.rs            # Error enum and Result type
│       │   ├── quic_varint.rs      # QUIC variable-length integer helpers
│       │   ├── server.rs           # HTTP/3 server (requires `h3` feature)
│       │   ├── settings.rs         # HTTP/3 settings constants and validation
│       │   ├── tls.rs              # TLS helpers (requires `h3`; self-signed cert helpers require `test-utils`)
│       │   └── types.rs            # Protocol / Session types
│       ├── tests/
│       │   ├── h3_connection.rs    # HTTP/3 integration tests (requires `h3`/`test-utils`)
│       │   └── integration_test.rs
│       └── examples/
│           ├── connect_udp_proxy.rs
│           ├── udp_echo_client.rs
│           └── udp_echo_server.rs
├── xtask/                  # Development helper crate
│   ├── Cargo.toml
│   └── src/main.rs
├── .cargo/config.toml      # Defines the `cargo xtask` alias
├── .github/workflows/ci.yml
├── README.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── SECURITY.md
└── LICENSE
```

### `crates/masque`

The main library. It is marked `publish = false`. Default builds have no
external dependencies. The optional `h3` feature adds `quinn`, `h3`, `h3-quinn`,
`rustls`, `tokio`, and `bytes`. Public modules:

- `capsule` — Capsule Protocol message format, types, and streaming parser.
- `capsule_protocol` — `Capsule-Protocol` header constant, parser, and
  serializer.
- `client` — HTTP/3 client scaffolding (`H3Client`), gated by the `h3` feature.
- `config` — `Config` with validated `SocketAddr` bind/peer addresses.
- `connect_udp` — `ConnectUdpRequest` and `CONNECT_UDP_METHOD` for RFC 9298
  CONNECT-UDP request targets and URI template parsing/generation.
- `datagram` — HTTP/3 Datagram payload types and encoding/decoding.
- `datagram_capsule` — DATAGRAM capsule encoder/decoder.
- `error` — `Error` enum (`InvalidConfig`, `InvalidVarInt`, `NotImplemented`,
  `InvalidConnectUdpRequest`, `Transport`, `InvalidCertificate`,
  `H3DatagramSetting`, `H3SettingsConflict`, `H3DatagramError`) and `Result`
  alias.
- `quic_varint` — QUIC variable-length integer encoding and decoding.
- `server` — HTTP/3 server scaffolding (`H3Server`, `H3Connection`), gated by
  the `h3` feature.
- `settings` — HTTP/3 setting constants such as `SETTINGS_H3_DATAGRAM`, the
  `H3DatagramSettingValue` newtype, and validation helpers.
- `tls` — TLS helpers. `H3_ALPN` is available when the `h3` feature is enabled;
  the self-signed certificate and verification-skipping helpers are gated by
  the `test-utils` feature.
- `types` — `Protocol` enum (`ConnectUdp`, `ConnectIp`, `ConnectEthernet`) and
  `Session`, which tracks negotiated capabilities such as HTTP/3 Datagrams.

The crate root enables `#![warn(missing_docs)]` and `#![warn(rust_2018_idioms)]`,
so new public items should be documented and idiomatic.

### `xtask`

A tiny development-task runner. It is invoked via the alias defined in
`.cargo/config.toml`:

```bash
cargo xtask ci          # run fmt, clippy, doc, and test (with and without the h3 feature)
cargo xtask fmt         # cargo fmt --all -- --check
cargo xtask clippy      # cargo clippy --workspace --all-targets --locked -- -D warnings
cargo xtask clippy-h3   # cargo clippy --workspace --all-targets --features masque/h3,masque/test-utils --locked -- -D warnings
cargo xtask doc         # cargo doc --workspace --no-deps --document-private-items --locked (RUSTDOCFLAGS=-D warnings)
cargo xtask doc-h3      # cargo doc --workspace --no-deps --document-private-items --features masque/h3,masque/test-utils --locked (RUSTDOCFLAGS=-D warnings)
cargo xtask test        # cargo test --workspace --locked
cargo xtask test-h3     # cargo test --workspace --features masque/h3,masque/test-utils --locked
cargo xtask help        # print usage
```

## Build and test commands

Use the standard Cargo toolchain. All commands should be run from the workspace
root unless noted otherwise.

```bash
# Run all workspace tests
cargo test --workspace --locked

# Run tests with the HTTP/3 transport scaffolding
cargo test --workspace --features masque/h3,masque/test-utils --locked

# Check formatting
cargo fmt --all -- --check

# Run clippy with warnings treated as errors
cargo clippy --workspace --all-targets --locked -- -D warnings

# Run clippy with the HTTP/3 feature (including test-utils so all h3 code is linted)
cargo clippy --workspace --all-targets --features masque/h3,masque/test-utils --locked -- -D warnings

# Build documentation; rustdoc warnings are errors
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked

# Build documentation with the HTTP/3 feature (including test-utils so all h3 docs are checked)
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --features masque/h3,masque/test-utils --locked

# Run the full development helper
cargo xtask ci
```

CI runs the same checks on `ubuntu-latest`, `windows-latest`, and
`macos-latest`. Formatting and documentation checks run only on Ubuntu.

## Examples

Examples live in `crates/masque/examples/` and are run with `--package masque`:

```bash
# UDP echo server (binds a UDP socket and echoes every datagram)
cargo run --package masque --example udp_echo_server -- 127.0.0.1:3456

# UDP echo client
cargo run --package masque --example udp_echo_client -- 127.0.0.1:3456 "hello"

# CONNECT-UDP proxy stub (currently exits with NotImplemented)
cargo run --package masque --example connect_udp_proxy -- 127.0.0.1:8443 127.0.0.1:53
```

The UDP echo programs are independent of HTTP/3 and are used for local
learning. The CONNECT-UDP proxy is a placeholder with TODOs.

## Code style guidelines

- Run `cargo fmt --all` before committing.
- Keep `cargo clippy --workspace --all-targets --locked -- -D warnings` clean.
- New public items must have documentation because the crate uses
  `#![warn(missing_docs)]`.
- Prefer `must_use` on pure accessor/query functions.
- Keep `Error` cloneable and `#[non_exhaustive]`; match the existing enum style.
- Store validated data in domain types (e.g., `Config` keeps `SocketAddr`, not
  raw strings).
- Add unit tests inside the source file (`#[cfg(test)] mod tests`) for internal
  details, and broader behavior tests in `crates/masque/tests/integration_test.rs`.
- Match the existing comment style: module-level doc comments, doc comments on
  public items, and inline comments only when they add non-obvious information.

## Communication guidelines

All project communication in GitHub is written in English. This keeps the
project accessible to a global audience and avoids ambiguity in technical
discussions.

**Language guardrail:** Before generating any text that will be posted to
GitHub — including PR titles, PR descriptions, review comments, review replies,
issue comments, and discussion posts — switch to English. Do not post in
Japanese or any other language, even if the reviewer or issue author used
another language.

- Write PR titles, descriptions, and review comments/replies in English.
- Write issue comments and GitHub Discussions in English.
- Write code comments, doc comments, commit messages, and documentation in
  English.
- Conversational replies to the local user may use the user's language, but any
  artifact that is committed or posted to GitHub must be in English.
- Avoid mixing languages, even when the original author used another language.

## Testing instructions

The test suite is split across three locations:

1. Unit tests in each source file (e.g., `config.rs`, `error.rs`, `types.rs`,
   `datagram.rs`, `capsule.rs`).
2. Integration tests in `crates/masque/tests/` that exercise the public API and
   spawn example binaries (notably `udp_echo_server`).
3. Unit tests in `xtask/src/main.rs` for the task-runner metadata.

Run everything with:

```bash
cargo test --workspace --locked
```

When adding new behavior, add or update tests. The integration test for the UDP
echo server builds the example binary and runs it as a child process, so
changes to example output may affect that test.

## Security considerations

- This project is a research and proof-of-concept scaffold. It is **not**
  intended for production use or exposure to untrusted networks.
- Only the latest commit on the `main` branch is supported.
- The UDP echo examples reflect traffic without authentication, encryption, or
  rate limiting. Run them only on `127.0.0.1` / localhost for local testing.
- Do not add secrets, private keys, or credentials to the repository. The
  `.gitignore` already excludes IDE directories and mutation-testing output.
- Report vulnerabilities privately through a GitHub Security Advisory rather
  than a public issue (see `SECURITY.md`).

## Planned architecture and dependencies

The library delegates QUIC and HTTP/3 to established crates. When the optional
`h3` feature is enabled, the following dependencies are used:

- `quinn` — async QUIC on `rustls` and `tokio`.
- `h3` / `h3-quinn` — HTTP/3 client/server over Quinn (`h3-quinn` is pinned to
  `0.0.10` because `0.0.8` is incompatible with `quinn` `0.11.11`).
- `rustls` — TLS 1.3 for QUIC handshakes.
- `tokio` — async runtime for examples and proxy demos.
- `rcgen` — self-signed certificate generation for the `test-utils` feature.
- `bytes` — byte buffer type used by the `h3` request/response bodies.

Default builds do not include HTTP/3 or QUIC dependencies.

## Roadmap (from `README.md`)

1. **Scaffold** (current) — workspace, core crate, examples, tests, CI.
2. **CONNECT-UDP PoC** — add HTTP/3 dependencies, implement CONNECT-UDP
   request handling, and map HTTP Datagrams to UDP.
3. **Validation** — integration tests against a local HTTP/3 server and spec
   edge cases.
4. **CONNECT-IP / CONNECT-Ethernet** — extend the library to additional MASQUE
   protocols.
5. **API stabilization** — refine public API, add documentation, and publish an
   early `masque` crate.

## What to do before committing

Run the full CI helper and fix any failures:

```bash
cargo xtask ci
```

This runs `cargo fmt --check`, `cargo clippy` (with and without `--features
masque/h3,masque/test-utils`), `cargo doc` with `RUSTDOCFLAGS=-D warnings` (with and without
`--features masque/h3,masque/test-utils`), and `cargo test` (with `--features masque/h3,masque/test-utils`
and without any feature).
