# CONNECT-UDP Request Type Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `ConnectUdpRequest`, its RFC 9298 URI template parser and
generator, and the `CONNECT_UDP_METHOD` constant.

**Architecture:** Add a focused `connect_udp` module with a validated request
type. URI parsing uses plain string operations to avoid new dependencies. Errors
are reported through a new `Error::InvalidConnectUdpRequest` variant. Public
items are re-exported from `lib.rs`.

**Tech Stack:** Rust 2024, no external dependencies.

## Global Constraints

- Minimum Supported Rust Version (MSRV): 1.85
- Workspace version: 0.0.1
- `cargo clippy --workspace --all-targets --locked -- -D warnings` must pass.
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked` must pass.
- New public items must have documentation (`#![warn(missing_docs)]`).
- `Error` must remain cloneable and `#[non_exhaustive]`.

---

### Task 1: Add `InvalidConnectUdpRequest` error variant

**Files:**
- Modify: `crates/masque/src/error.rs:18-91`
- Test: `crates/masque/src/error.rs`

**Interfaces:**
- Produces: `Error::InvalidConnectUdpRequest { field, message }`

- [ ] **Step 1: Add the variant and display format**

```rust
/// The provided CONNECT-UDP request was invalid.
InvalidConnectUdpRequest {
    /// The request field that caused the error.
    field: &'static str,
    /// A human-readable description of what is wrong.
    message: String,
},
```

Add the corresponding `Display` arm:

```rust
Error::InvalidConnectUdpRequest { field, message } => {
    write!(f, "invalid CONNECT-UDP request for {field}: {message}")
}
```

- [ ] **Step 2: Add a unit test for the display format**

```rust
#[test]
fn invalid_connect_udp_request_display_includes_field_and_message() {
    let err = Error::InvalidConnectUdpRequest {
        field: "target_port",
        message: "must be a valid port".into(),
    };
    assert_eq!(
        err.to_string(),
        "invalid CONNECT-UDP request for target_port: must be a valid port"
    );
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test --package masque error`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/masque/src/error.rs
git commit -m "feat: add InvalidConnectUdpRequest error variant"
```

---

### Task 2: Implement `ConnectUdpRequest`

**Files:**
- Create: `crates/masque/src/connect_udp.rs`
- Test: inside `crates/masque/src/connect_udp.rs`

**Interfaces:**
- Consumes: `Error::InvalidConnectUdpRequest` from Task 1
- Produces:
  - `pub const CONNECT_UDP_METHOD: &str = "CONNECT-UDP"`
  - `pub struct ConnectUdpRequest { target_host: String, target_port: u16, udp_proxy_config: Option<String> }`
  - `impl ConnectUdpRequest`
    - `pub fn new(target_host: impl Into<String>, target_port: u16, udp_proxy_config: Option<impl Into<String>>) -> Result<Self>`
    - `pub fn from_uri(uri: &str) -> Result<Self>`
    - `pub fn to_uri(&self, proxy_authority: &str) -> String`
    - `pub fn target_host(&self) -> &str`
    - `pub fn target_port(&self) -> u16`
    - `pub fn udp_proxy_config(&self) -> Option<&str>`

- [ ] **Step 1: Write the first failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_stores_valid_fields() {
        let req = ConnectUdpRequest::new("example.com", 443, None::<String>).unwrap();
        assert_eq!(req.target_host(), "example.com");
        assert_eq!(req.target_port(), 443);
        assert_eq!(req.udp_proxy_config(), None);
    }
}
```

Run: `cargo test --package masque connect_udp`
Expected: FAIL (module/type not found)

- [ ] **Step 2: Create the module skeleton and constant**

Create `crates/masque/src/connect_udp.rs`:

```rust
//! CONNECT-UDP request type and URI template helpers.

use crate::{Error, Result};

/// The HTTP method used for CONNECT-UDP requests per RFC 9298.
pub const CONNECT_UDP_METHOD: &str = "CONNECT-UDP";

/// A parsed CONNECT-UDP request per RFC 9298.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectUdpRequest {
    target_host: String,
    target_port: u16,
    udp_proxy_config: Option<String>,
}

impl ConnectUdpRequest {
    /// Create a new CONNECT-UDP request.
    pub fn new(
        target_host: impl Into<String>,
        target_port: u16,
        udp_proxy_config: Option<impl Into<String>>,
    ) -> Result<Self> {
        let target_host = target_host.into();
        validate_target_host(&target_host)?;
        validate_target_port(target_port)?;
        Ok(Self {
            target_host,
            target_port,
            udp_proxy_config: udp_proxy_config.map(Into::into),
        })
    }

    /// Parse a CONNECT-UDP request from an RFC 9298 URI template.
    pub fn from_uri(uri: &str) -> Result<Self> {
        let (_scheme_authority, path_and_query) = uri.split_once("/masque")
            .ok_or_else(|| Error::InvalidConnectUdpRequest {
                field: "path",
                message: "URI must contain '/masque' path".into(),
            })?;

        let query = path_and_query.strip_prefix("/masque").unwrap_or(path_and_query);
        let query = query.strip_prefix('?').unwrap_or(query);

        let mut target_host: Option<String> = None;
        let mut target_port: Option<u16> = None;
        let mut udp_proxy_config: Option<String> = None;

        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = pair.split_once('=').ok_or_else(|| Error::InvalidConnectUdpRequest {
                field: "query",
                message: format!("query parameter '{pair}' is missing '='"),
            })?;
            match key {
                "target_host" => target_host = Some(value.into()),
                "target_port" => {
                    let port = value.parse::<u16>().map_err(|_| Error::InvalidConnectUdpRequest {
                        field: "target_port",
                        message: format!("'{value}' is not a valid port number"),
                    })?;
                    validate_target_port(port)?;
                    target_port = Some(port);
                }
                "udp_proxy_config" => udp_proxy_config = Some(value.into()),
                _ => {}
            }
        }

        let target_host = target_host.ok_or_else(|| Error::InvalidConnectUdpRequest {
            field: "target_host",
            message: "missing query parameter 'target_host'".into(),
        })?;
        validate_target_host(&target_host)?;

        let target_port = target_port.ok_or_else(|| Error::InvalidConnectUdpRequest {
            field: "target_port",
            message: "missing query parameter 'target_port'".into(),
        })?;

        Ok(Self {
            target_host,
            target_port,
            udp_proxy_config,
        })
    }

    /// Generate the RFC 9298 URI for this request.
    pub fn to_uri(&self, proxy_authority: &str) -> String {
        let mut uri = format!(
            "https://{proxy_authority}/masque?target_host={}&target_port={}",
            self.target_host, self.target_port
        );
        if let Some(config) = &self.udp_proxy_config {
            uri.push_str("&udp_proxy_config=");
            uri.push_str(config);
        }
        uri
    }

    /// Return the target host.
    #[must_use]
    pub fn target_host(&self) -> &str {
        &self.target_host
    }

    /// Return the target port.
    #[must_use]
    pub fn target_port(&self) -> u16 {
        self.target_port
    }

    /// Return the optional UDP proxy configuration.
    #[must_use]
    pub fn udp_proxy_config(&self) -> Option<&str> {
        self.udp_proxy_config.as_deref()
    }
}

fn validate_target_host(host: &str) -> Result<()> {
    if host.trim().is_empty() {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_host",
            message: "must not be empty".into(),
        });
    }
    Ok(())
}

fn validate_target_port(port: u16) -> Result<()> {
    if port == 0 {
        return Err(Error::InvalidConnectUdpRequest {
            field: "target_port",
            message: "must be between 1 and 65535".into(),
        });
    }
    Ok(())
}
```

Run: `cargo test --package masque connect_udp`
Expected: PASS for the first test

- [ ] **Step 3: Add remaining unit tests one by one**

Add after the first test:

```rust
#[test]
fn request_accepts_optional_udp_proxy_config() {
    let req = ConnectUdpRequest::new("example.com", 443, Some("config1")).unwrap();
    assert_eq!(req.udp_proxy_config(), Some("config1"));
}

#[test]
fn request_rejects_empty_target_host() {
    let err = ConnectUdpRequest::new("", 443, None::<String>).unwrap_err();
    assert!(matches!(
        err,
        Error::InvalidConnectUdpRequest {
            field: "target_host",
            ..
        }
    ));
}

#[test]
fn request_rejects_zero_target_port() {
    let err = ConnectUdpRequest::new("example.com", 0, None::<String>).unwrap_err();
    assert!(err.to_string().contains("target_port"));
}

#[test]
fn from_uri_parses_minimal_template() {
    let req = ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_host=target.example&target_port=53").unwrap();
    assert_eq!(req.target_host(), "target.example");
    assert_eq!(req.target_port(), 53);
    assert_eq!(req.udp_proxy_config(), None);
}

#[test]
fn from_uri_parses_template_with_udp_proxy_config() {
    let req = ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_host=target.example&target_port=53&udp_proxy_config=cfg").unwrap();
    assert_eq!(req.udp_proxy_config(), Some("cfg"));
}

#[test]
fn from_uri_and_to_uri_round_trip() {
    let original = ConnectUdpRequest::new("target.example", 53, Some("cfg")).unwrap();
    let uri = original.to_uri("proxy.example:443");
    let parsed = ConnectUdpRequest::from_uri(&uri).unwrap();
    assert_eq!(original, parsed);
}

#[test]
fn from_uri_rejects_missing_target_host() {
    let err = ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_port=53").unwrap_err();
    assert!(err.to_string().contains("target_host"));
}

#[test]
fn from_uri_rejects_missing_target_port() {
    let err = ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_host=target.example").unwrap_err();
    assert!(err.to_string().contains("target_port"));
}

#[test]
fn from_uri_rejects_non_numeric_target_port() {
    let err = ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_host=target.example&target_port=abc").unwrap_err();
    assert!(err.to_string().contains("target_port"));
}

#[test]
fn from_uri_rejects_zero_target_port() {
    let err = ConnectUdpRequest::from_uri("https://proxy.example:443/masque?target_host=target.example&target_port=0").unwrap_err();
    assert!(err.to_string().contains("target_port"));
}

#[test]
fn from_uri_rejects_missing_masque_path() {
    let err = ConnectUdpRequest::from_uri("https://proxy.example:443/other?target_host=target.example&target_port=53").unwrap_err();
    assert!(err.to_string().contains("path"));
}
```

Run: `cargo test --package masque connect_udp`
Expected: PASS

- [ ] **Step 4: Run clippy**

Run: `cargo clippy --package masque --all-targets --locked -- -D warnings`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add crates/masque/src/connect_udp.rs
git commit -m "feat: add CONNECT-UDP request type and URI parser"
```

---

### Task 3: Wire public exports

**Files:**
- Modify: `crates/masque/src/lib.rs:29-50`

**Interfaces:**
- Consumes: `ConnectUdpRequest` and `CONNECT_UDP_METHOD` from Task 2
- Produces: public re-exports at crate root

- [ ] **Step 1: Add module declaration and re-exports**

```rust
pub mod connect_udp;
```

```rust
pub use connect_udp::{CONNECT_UDP_METHOD, ConnectUdpRequest};
```

- [ ] **Step 2: Add integration tests**

Modify `crates/masque/tests/integration_test.rs` and append:

```rust
#[test]
fn connect_udp_request_round_trips_through_public_api() {
    let req = masque::ConnectUdpRequest::new("target.example", 53, Some("cfg")).unwrap();
    assert_eq!(req.target_host(), "target.example");
    assert_eq!(req.target_port(), 53);
    assert_eq!(req.udp_proxy_config(), Some("cfg"));

    let uri = req.to_uri("proxy.example:443");
    let parsed = masque::ConnectUdpRequest::from_uri(&uri).unwrap();
    assert_eq!(parsed.target_host(), "target.example");
    assert_eq!(parsed.target_port(), 53);
    assert_eq!(parsed.udp_proxy_config(), Some("cfg"));
}

#[test]
fn connect_udp_method_constant_is_accessible_at_crate_root() {
    assert_eq!(masque::CONNECT_UDP_METHOD, "CONNECT-UDP");
}

#[test]
fn connect_udp_request_rejects_invalid_port_from_public_api() {
    let err = masque::ConnectUdpRequest::new("target.example", 0, None::<String>).unwrap_err();
    assert!(err.to_string().contains("target_port"));
}
```

- [ ] **Step 3: Run tests**

Run: `cargo test --workspace --locked`
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add crates/masque/src/lib.rs crates/masque/tests/integration_test.rs
git commit -m "feat: expose ConnectUdpRequest at crate root and add integration tests"
```

---

### Task 4: Final verification

**Files:** all changed files

- [ ] **Step 1: Run formatter check**

Run: `cargo fmt --all -- --check`
Expected: PASS

- [ ] **Step 2: Run clippy**

Run: `cargo clippy --workspace --all-targets --locked -- -D warnings`
Expected: PASS

- [ ] **Step 3: Build docs**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --document-private-items --locked`
Expected: PASS

- [ ] **Step 4: Run full test suite**

Run: `cargo test --workspace --locked`
Expected: PASS

- [ ] **Step 5: Final commit if any formatting changes**

```bash
git add -A
git commit -m "style: apply cargo fmt" || true
```
