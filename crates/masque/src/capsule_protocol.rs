//! Helpers for the `Capsule-Protocol` header field.
//!
//! `Capsule-Protocol` is a Boolean Structured Field as defined in RFC 9297
//! Section 3.4 and serialized according to RFC 8941. Because MASQUE operates
//! over HTTP/3, the wire-format header-name constant is exposed in lowercase
//! per RFC 9114.

/// The HTTP/3 wire-format `Capsule-Protocol` header field name.
///
/// RFC 9114 requires field names to be lowercase when encoded in HTTP/3. This
/// constant uses `capsule-protocol` so callers can pass it directly to HTTP/3
/// header APIs without additional normalization.
pub const CAPSULE_PROTOCOL: &str = "capsule-protocol";

/// Parse a `Capsule-Protocol` header value as a Boolean Structured Field.
///
/// Returns `Some(true)` for `?1` and `Some(false)` for `?0`. Optional
/// surrounding whitespace (SP / HTAB) and unknown parameters are handled as
/// required by RFC 8941 and RFC 9297. Returns `None` for empty or malformed
/// input, or for non-boolean values.
///
/// Per RFC 9297 Section 3.4, a `false` value has the same semantics as the
/// header being absent. Callers that want to detect Capsule Protocol support
/// should therefore check `result == Some(true)` rather than `is_some()`.
#[must_use]
pub fn parse_capsule_protocol(value: &str) -> Option<bool> {
    let value = trim_sp(value);
    let bytes = value.as_bytes();

    if bytes.len() < 2 || bytes[0] != b'?' {
        return None;
    }

    let flag = match bytes[1] {
        b'1' => true,
        b'0' => false,
        _ => return None,
    };

    let rest = &bytes[2..];
    if rest.is_empty() {
        return Some(flag);
    }

    if rest[0] != b';' {
        return None;
    }

    parse_parameters(rest)?;
    Some(flag)
}

/// Serialize a boolean as a `Capsule-Protocol` header value.
///
/// Returns `?1` for `true` and `?0` for `false`.
#[must_use]
pub const fn serialize_capsule_protocol(value: bool) -> &'static str {
    if value { "?1" } else { "?0" }
}

/// Strip optional leading and trailing SP characters as allowed by RFC 8941.
fn trim_sp(value: &str) -> &str {
    value.trim_start_matches(' ').trim_end_matches(' ')
}

/// Validate the remainder of a Boolean Item, which consists only of parameters.
fn parse_parameters(mut input: &[u8]) -> Option<()> {
    while !input.is_empty() {
        if input[0] != b';' {
            return None;
        }
        input = skip_sp(&input[1..]);

        let (key, rest) = parse_key(input)?;
        if key.is_empty() {
            return None;
        }
        input = rest;

        if input.first() == Some(&b'=') {
            input = &input[1..];
            let (_, rest) = parse_bare_item(input)?;
            input = rest;
        }
    }

    Some(())
}

/// Parse a parameter key and return the key plus the remaining input.
fn parse_key(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.is_empty() {
        return None;
    }

    let first = input[0];
    if !(first.is_ascii_lowercase() || first == b'*') {
        return None;
    }

    let mut i = 1;
    while i < input.len() && is_key_char(input[i]) {
        i += 1;
    }

    Some((&input[..i], &input[i..]))
}

fn is_key_char(c: u8) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'_' | b'-' | b'.' | b'*')
}

/// Parse a bare Item and return the consumed slice plus the remaining input.
fn parse_bare_item(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.is_empty() {
        return None;
    }

    match input[0] {
        b'-' | b'0'..=b'9' => parse_number(input),
        b'"' => parse_string(input),
        b':' => parse_binary(input),
        b'?' => parse_boolean_value(input),
        _ if input[0].is_ascii_alphabetic() || input[0] == b'*' => parse_token(input),
        _ => None,
    }
}

/// Parse an integer or decimal bare item.
fn parse_number(input: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut i = 0;

    if input.get(i) == Some(&b'-') {
        i += 1;
    }

    let int_start = i;
    while i < input.len() && input[i].is_ascii_digit() {
        i += 1;
    }

    let int_digits = i - int_start;
    if int_digits == 0 || int_digits > 15 {
        return None;
    }

    if input.get(i) == Some(&b'.') {
        if int_digits > 12 {
            return None;
        }
        i += 1;
        let frac_start = i;
        while i < input.len() && input[i].is_ascii_digit() {
            i += 1;
        }
        let frac_digits = i - frac_start;
        if frac_digits == 0 || frac_digits > 3 {
            return None;
        }
    }

    Some((&input[..i], &input[i..]))
}

/// Parse a string bare item.
fn parse_string(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input[0] != b'"' {
        return None;
    }

    let mut i = 1;
    while i < input.len() {
        match input[i] {
            b'\\' => {
                if i + 1 >= input.len() {
                    return None;
                }
                let next = input[i + 1];
                if next != b'"' && next != b'\\' {
                    return None;
                }
                i += 2;
            }
            b'"' => return Some((&input[..i + 1], &input[i + 1..])),
            0x00..=0x1f | 0x7f..=0xff => return None,
            _ => i += 1,
        }
    }

    None
}

/// Parse a binary bare item.
fn parse_binary(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input[0] != b':' {
        return None;
    }

    let mut i = 1;
    while i < input.len() {
        if input[i] == b':' {
            let content = &input[1..i];
            if !is_valid_base64(content) {
                return None;
            }
            return Some((&input[..i + 1], &input[i + 1..]));
        }
        i += 1;
    }

    None
}

fn is_valid_base64(input: &[u8]) -> bool {
    if input.len() % 4 != 0 {
        return false;
    }

    let mut padding = 0;
    for (i, &c) in input.iter().enumerate() {
        if c == b'=' {
            if i + 2 < input.len() {
                return false;
            }
            padding += 1;
        } else if padding > 0 || !is_base64_char(c) {
            return false;
        }
    }

    padding <= 2
}

fn is_base64_char(c: u8) -> bool {
    c.is_ascii_alphabetic() || c.is_ascii_digit() || matches!(c, b'+' | b'/')
}

/// Parse a token bare item.
fn parse_token(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.is_empty() {
        return None;
    }

    let first = input[0];
    if !(first.is_ascii_alphabetic() || first == b'*') {
        return None;
    }

    let mut i = 1;
    while i < input.len() && is_token_char(input[i]) {
        i += 1;
    }

    Some((&input[..i], &input[i..]))
}

fn is_token_char(c: u8) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
                | b':'
                | b'/'
        )
}

/// Parse a boolean bare item (`?0` or `?1`).
fn parse_boolean_value(input: &[u8]) -> Option<(&[u8], &[u8])> {
    if input.len() < 2 || input[0] != b'?' {
        return None;
    }

    match input[1] {
        b'0' | b'1' => Some((&input[..2], &input[2..])),
        _ => None,
    }
}

/// Skip optional SP characters (RFC 8941 allows `*SP` after `;`).
fn skip_sp(input: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < input.len() && input[i] == b' ' {
        i += 1;
    }
    &input[i..]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capsule_protocol_header_name_is_lowercase() {
        assert_eq!(CAPSULE_PROTOCOL, "capsule-protocol");
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
    fn parse_leading_and_trailing_sp_returns_boolean() {
        assert_eq!(parse_capsule_protocol(" ?1"), Some(true));
        assert_eq!(parse_capsule_protocol("?1 "), Some(true));
        assert_eq!(parse_capsule_protocol("  ?1  "), Some(true));
    }

    #[test]
    fn parse_leading_or_trailing_htab_returns_none() {
        assert_eq!(parse_capsule_protocol("\t?1"), None);
        assert_eq!(parse_capsule_protocol("?1\t"), None);
        assert_eq!(parse_capsule_protocol("\t?0\t"), None);
    }

    #[test]
    fn parse_whitespace_after_parameter_separator_returns_boolean() {
        assert_eq!(parse_capsule_protocol("?1; foo=bar"), Some(true));
        assert_eq!(parse_capsule_protocol("?0; foo"), Some(false));
    }

    #[test]
    fn parse_whitespace_before_parameter_separator_returns_none() {
        assert_eq!(parse_capsule_protocol("?1 ;foo=bar"), None);
        assert_eq!(parse_capsule_protocol("?0\t;foo"), None);
    }

    #[test]
    fn parse_unknown_parameters_returns_boolean() {
        assert_eq!(parse_capsule_protocol("?1;foo=bar"), Some(true));
        assert_eq!(parse_capsule_protocol("?0;foo"), Some(false));
        assert_eq!(parse_capsule_protocol(" ?1;ext=1 "), Some(true));
        assert_eq!(
            parse_capsule_protocol("?1;a=1;b=?0;c=:dGVzdA==:"),
            Some(true)
        );
    }

    #[test]
    fn parse_invalid_value_returns_none() {
        assert_eq!(parse_capsule_protocol("true"), None);
        assert_eq!(parse_capsule_protocol("false"), None);
        assert_eq!(parse_capsule_protocol("1"), None);
        assert_eq!(parse_capsule_protocol("?2"), None);
        assert_eq!(parse_capsule_protocol("?1foo"), None);
        // Non-ASCII after `?` must not panic on a char boundary.
        assert_eq!(parse_capsule_protocol("?é"), None);
        assert_eq!(parse_capsule_protocol(" ?é "), None);
    }

    #[test]
    fn parse_malformed_parameters_returns_none() {
        assert_eq!(parse_capsule_protocol("?1;"), None);
        assert_eq!(parse_capsule_protocol("?1;Bad"), None);
        assert_eq!(parse_capsule_protocol("?1;foo=\"unterminated"), None);
        assert_eq!(parse_capsule_protocol("?1;foo =bar"), None);
        assert_eq!(parse_capsule_protocol("?1;foo=?"), None);
        assert_eq!(parse_capsule_protocol("?1;foo=:="), None);
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
    fn parse_number_parameter_limits_are_enforced() {
        // Integer with more than 15 digits.
        assert_eq!(parse_capsule_protocol("?1;foo=1234567890123456"), None);
        // Decimal with more than 12 integer digits.
        assert_eq!(parse_capsule_protocol("?1;foo=1234567890123.0"), None);
        // Decimal with more than 3 fractional digits.
        assert_eq!(parse_capsule_protocol("?1;foo=1.1234"), None);
    }

    #[test]
    fn parse_string_parameter_rejects_non_ascii() {
        assert_eq!(parse_capsule_protocol("?1;foo=\"é\""), None);
    }

    #[test]
    fn parse_empty_or_whitespace_value_returns_none() {
        assert_eq!(parse_capsule_protocol(""), None);
        assert_eq!(parse_capsule_protocol("   "), None);
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
