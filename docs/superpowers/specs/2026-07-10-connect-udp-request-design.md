# CONNECT-UDP Request Type and URI Template Parser

## Goal

Add a public `ConnectUdpRequest` type that represents an RFC 9298 CONNECT-UDP
request, including parsing and generation of the RFC 9298 Section 3.1 URI
template.

## Architecture

A new `connect_udp` module owns the request type and URI logic. The type stores
the validated `target_host`, `target_port`, and optional `udp_proxy_config`.
Parsing is implemented with plain string operations to keep the crate free of
external URI dependencies. Errors reuse the crate's `Error` enum via a new
`InvalidConnectUdpRequest` variant so callers get a typed, cloneable error with a
clear field name and message.

## Public API

- `pub const CONNECT_UDP_METHOD: &str = "CONNECT-UDP"`
- `pub struct ConnectUdpRequest { target_host, target_port, udp_proxy_config }`
  - `ConnectUdpRequest::new(target_host, target_port, udp_proxy_config) -> Result<Self>`
  - `ConnectUdpRequest::from_uri(uri: &str) -> Result<Self>`
  - `ConnectUdpRequest::to_uri(&self, proxy_authority: &str) -> String`
  - Accessors: `target_host()`, `target_port()`, `udp_proxy_config()`

## URI Template

RFC 9298 Section 3.1:

```text
https://<proxy>:<port>/masque?target_host=<target>&target_port=<port>
```

Optional query parameter: `udp_proxy_config=<config>`.

`from_uri` extracts the path `/masque` and the query parameters.
`to_uri` builds the full URI from a caller-supplied proxy authority
(`host:port`).

## Validation

- `target_host`: must be non-empty after trimming.
- `target_port`: must be a valid `u16` in the range `1..=65535`.
- `udp_proxy_config`: optional; when present, stored as-is.

## Error Handling

Add `Error::InvalidConnectUdpRequest { field, message }`, cloneable and
consistent with existing `InvalidConfig` formatting.

## Testing

Unit tests inside `connect_udp.rs` cover:

- Valid construction with and without `udp_proxy_config`.
- URI parsing round-trip.
- Missing `target_host` or `target_port`.
- Malformed port (non-numeric, zero, out of range).
- Unexpected path or missing `/masque`.

Integration tests in `tests/integration_test.rs` exercise the public API from
the crate root.
