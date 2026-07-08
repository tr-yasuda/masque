//! HTTP/3 settings used by MASQUE protocols, including `SETTINGS_H3_DATAGRAM`
//! for negotiating HTTP/3 Datagram support (RFC 9297 Section 2.1.1).

use crate::{Error, Result};

/// HTTP/3 setting for datagram support (RFC 9297 Section 2.1.1).
///
/// Note that this setting identifier has the same numeric value (`0x33`) as the
/// `H3_DATAGRAM_ERROR` error code (`crate::H3_DATAGRAM_ERROR_CODE`), but the
/// two belong to different namespaces and must not be used interchangeably.
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// A validated value for the `SETTINGS_H3_DATAGRAM` HTTP/3 setting.
///
/// RFC 9297 Section 2.1.1 limits this setting to `0` or `1`. This newtype
/// makes that constraint explicit at the type level and prevents accidental
/// use of the setting identifier (`0x33`) where a setting value is expected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H3DatagramSettingValue(u64);

impl H3DatagramSettingValue {
    /// Setting value `0`: the endpoint is not willing to use HTTP/3 Datagrams.
    pub const DISABLED: Self = Self(0);

    /// Setting value `1`: the endpoint is willing to use HTTP/3 Datagrams.
    pub const ENABLED: Self = Self(1);

    /// Create a new validated setting value.
    ///
    /// # Errors
    ///
    /// Returns [`Error::H3DatagramSetting`] if `value` is not `0` or `1`.
    pub fn new(value: u64) -> Result<Self> {
        if value == 0 || value == 1 {
            Ok(Self(value))
        } else {
            Err(Error::H3DatagramSetting {
                setting: SETTINGS_H3_DATAGRAM,
                value,
            })
        }
    }

    /// Return the raw numeric setting value.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }

    /// Return whether this value enables HTTP/3 Datagrams.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.0 == 1
    }
}

/// Validate the raw value of an HTTP/3 Datagram setting.
///
/// RFC 9297 Section 2.1.1 limits this setting to `0` or `1`. Prefer
/// [`H3DatagramSettingValue::new`] when the validated value itself is needed.
///
/// # Errors
///
/// Returns [`Error::H3DatagramSetting`] if `value` is not `0` or `1`.
pub fn validate_h3_datagram_setting_value(value: u64) -> Result<()> {
    H3DatagramSettingValue::new(value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_h3_datagram_constant_matches_rfc9297() {
        assert_eq!(SETTINGS_H3_DATAGRAM, 0x33);
    }

    #[test]
    fn h3_datagram_setting_value_accepts_zero() {
        let v = H3DatagramSettingValue::new(0).unwrap();
        assert_eq!(v.get(), 0);
        assert!(!v.is_enabled());
        assert_eq!(v, H3DatagramSettingValue::DISABLED);
    }

    #[test]
    fn h3_datagram_setting_value_accepts_one() {
        let v = H3DatagramSettingValue::new(1).unwrap();
        assert_eq!(v.get(), 1);
        assert!(v.is_enabled());
        assert_eq!(v, H3DatagramSettingValue::ENABLED);
    }

    #[test]
    fn h3_datagram_setting_value_rejects_two() {
        let err = H3DatagramSettingValue::new(2).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramSetting {
                setting: SETTINGS_H3_DATAGRAM,
                value: 2,
            }
        ));
        assert_eq!(
            err.to_string(),
            "invalid HTTP/3 datagram setting 0x33: value must be 0 or 1, got 2"
        );
    }

    #[test]
    fn h3_datagram_setting_value_rejects_large_value() {
        let err = H3DatagramSettingValue::new(u64::MAX).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramSetting {
                setting: SETTINGS_H3_DATAGRAM,
                value: u64::MAX,
            }
        ));
    }

    #[test]
    fn validate_helper_accepts_zero_and_one() {
        assert!(validate_h3_datagram_setting_value(0).is_ok());
        assert!(validate_h3_datagram_setting_value(1).is_ok());
    }

    #[test]
    fn validate_helper_rejects_invalid_values() {
        let err = validate_h3_datagram_setting_value(2).unwrap_err();
        assert!(matches!(
            err,
            Error::H3DatagramSetting {
                setting: SETTINGS_H3_DATAGRAM,
                value: 2,
            }
        ));
        assert_eq!(
            err.to_string(),
            "invalid HTTP/3 datagram setting 0x33: value must be 0 or 1, got 2"
        );
    }

    #[test]
    fn validate_helper_and_newtype_produce_identical_errors() {
        for value in [2, u64::MAX] {
            let helper_err = validate_h3_datagram_setting_value(value).unwrap_err();
            let newtype_err = H3DatagramSettingValue::new(value).unwrap_err();
            assert_eq!(helper_err.to_string(), newtype_err.to_string());
            assert_eq!(helper_err, newtype_err);
        }
    }
}
