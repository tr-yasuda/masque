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
library currently exposes only configuration primitives, error types, and
placeholder types for protocols and sessions. Examples are plain UDP echo
programs and a CONNECT-UDP proxy stub.

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
│       │   ├── lib.rs      # Crate root; re-exports public API
│       │   ├── config.rs   # Config validation and parsing
│       │   ├── error.rs    # Error enum and Result type
│       │   └── types.rs    # Protocol / Session placeholders
│       ├── tests/
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

The main library. It currently has no external dependencies and is marked
`publish = false`. Public modules:

- `config` — `Config` with validated `SocketAddr` bind/peer addresses.
- `error` — `Error` enum (`InvalidConfig`, `NotImplemented`) and `Result` alias.
- `types` — `Protocol` enum (`ConnectUdp`, `ConnectIp`, `ConnectEthernet`) and
  a placeholder `Session` type.

The crate root enables `#![warn(missing_docs)]` and `#![warn(rust_2018_idioms)]`,
so new public items should be documented and idiomatic.

### `xtask`

A tiny development-task runner. It is invoked via the alias defined in
`.cargo/config.toml`:

```bash
cargo xtask ci      # run fmt, clippy, doc, and test
cargo xtask fmt     # cargo fmt --all -- --check
cargo xtask clippy  # cargo clippy --workspace --all-targets --locked -- -D warnings
cargo xtask doc     # cargo doc --workspace --no-deps --document-private-items --locked (RUSTDOCFLAGS=-D warnings)
cargo xtask test    # cargo test --workspace --locked
cargo xtask help    # print usage
```

## Build and test commands

Use the standard Cargo toolchain. All commands should be run from the workspace
root unless noted otherwise.

```bash
# Run all workspace tests
cargo test --workspace --locked

# Check formatting
cargo fmt --all -- --check

# Run clippy with warnings treated as errors
cargo clippy --workspace --all-targets --locked -- -D warnings

# Build documentation; rustdoc warnings are errors
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked

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

## Testing instructions

The test suite is split across three locations:

1. Unit tests in each source file (`config.rs`, `error.rs`, `types.rs`).
2. Integration tests in `crates/masque/tests/integration_test.rs` that exercise
   the public API and spawn example binaries (notably `udp_echo_server`).
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

The library is designed to delegate QUIC and HTTP/3 to established crates.
Candidate dependencies under evaluation (not yet added):

- `quinn` — async QUIC on `rustls` and `tokio`.
- `h3` / `h3-quinn` — HTTP/3 client/server over Quinn.
- `rustls` — TLS 1.3 for QUIC handshakes.
- `tokio` — async runtime for examples and proxy demos.

No HTTP/3 or QUIC dependencies are present yet. The first step is to stabilize
core types and example structure before integrating transport crates.

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

This is equivalent to running `cargo fmt --check`, `cargo clippy`,
`cargo doc` with `RUSTDOCFLAGS=-D warnings`, and `cargo test`.
