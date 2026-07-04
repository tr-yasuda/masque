//! Helpers for the `Capsule-Protocol` header field.
//!
//! `Capsule-Protocol` is a Boolean Structured Field as defined in RFC 9297
//! Section 3.4 and serialized according to RFC 8941.

/// The `Capsule-Protocol` header field name.
pub const CAPSULE_PROTOCOL: &str = "Capsule-Protocol";

/// Parse a `Capsule-Protocol` header value as a Boolean Structured Field.
///
/// Returns `Some(true)` for `?1` and `Some(false)` for `?0`. Optional
/// surrounding whitespace (SP / HTAB) and trailing parameters are ignored, as
/// required by RFC 8941 and RFC 9297. Returns `None` for empty or malformed
/// input, or for non-boolean values.
///
/// Per RFC 9297 Section 3.4, a `false` value has the same semantics as the
/// header being absent. Callers that want to detect Capsule Protocol support
/// should therefore check `result == Some(true)` rather than `is_some()`.
#[must_use]
pub fn parse_capsule_protocol(value: &str) -> Option<bool> {
    let value = trim_ows(value);
    if value.len() < 2 || value.as_bytes()[0] != b'?' {
        return None;
    }

    let rest = &value[2..];
    match value.as_bytes()[1] {
        b'1' if rest.is_empty() || rest.starts_with(';') => Some(true),
        b'0' if rest.is_empty() || rest.starts_with(';') => Some(false),
        _ => None,
    }
}

/// Serialize a boolean as a `Capsule-Protocol` header value.
///
/// Returns `?1` for `true` and `?0` for `false`.
#[must_use]
pub const fn serialize_capsule_protocol(value: bool) -> &'static str {
    if value { "?1" } else { "?0" }
}

/// Strip optional leading and trailing whitespace as allowed by RFC 8941.
fn trim_ows(value: &str) -> &str {
    value
        .trim_start_matches([' ', '\t'])
        .trim_end_matches([' ', '\t'])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_protocol_header_name_is_defined() {
        assert_eq!(CAPSULE_PROTOCOL, "Capsule-Protocol");
    }

    #[test]
    fn parse_true_boolean_value_returns_some_true() {
        assert_eq!(parse_capsule_protocol("?1"), Some(true));
    }

    #[test]
    fn parse_false_boolean_value_returns_some_false() {
        assert_eq!(parse_capsule_protocol("?0"), Some(false));
    }

    #[test]
    fn parse_leading_and_trailing_whitespace_returns_boolean() {
        assert_eq!(parse_capsule_protocol(" ?1"), Some(true));
        assert_eq!(parse_capsule_protocol("?1 "), Some(true));
        assert_eq!(parse_capsule_protocol("  ?1  "), Some(true));
        assert_eq!(parse_capsule_protocol("\t?0\t"), Some(false));
    }

    #[test]
    fn parse_unknown_parameters_returns_boolean() {
        assert_eq!(parse_capsule_protocol("?1;foo=bar"), Some(true));
        assert_eq!(parse_capsule_protocol("?0;foo"), Some(false));
        assert_eq!(parse_capsule_protocol(" ?1;ext=1 "), Some(true));
    }

    #[test]
    fn parse_invalid_value_returns_none() {
        assert_eq!(parse_capsule_protocol("true"), None);
        assert_eq!(parse_capsule_protocol("false"), None);
        assert_eq!(parse_capsule_protocol("1"), None);
        assert_eq!(parse_capsule_protocol("?2"), None);
        assert_eq!(parse_capsule_protocol("?1foo"), None);
    }

    #[test]
    fn parse_non_boolean_structured_field_values_returns_none() {
        assert_eq!(parse_capsule_protocol("\"foo\""), None);
        assert_eq!(parse_capsule_protocol("foo"), None);
        assert_eq!(parse_capsule_protocol("42"), None);
        assert_eq!(parse_capsule_protocol(":abc:"), None);
        assert_eq!(parse_capsule_protocol("?1, ?1"), None);
    }

    #[test]
    fn parse_empty_or_whitespace_value_returns_none() {
        assert_eq!(parse_capsule_protocol(""), None);
        assert_eq!(parse_capsule_protocol("   "), None);
        assert_eq!(parse_capsule_protocol("\t\t"), None);
    }

    #[test]
    fn parse_and_serialize_round_trip() {
        for value in [true, false] {
            assert_eq!(
                parse_capsule_protocol(serialize_capsule_protocol(value)),
                Some(value)
            );
        }
    }

    #[test]
    fn serialize_true_returns_boolean_one() {
        assert_eq!(serialize_capsule_protocol(true), "?1");
    }

    #[test]
    fn serialize_false_returns_boolean_zero() {
        assert_eq!(serialize_capsule_protocol(false), "?0");
    }
}
