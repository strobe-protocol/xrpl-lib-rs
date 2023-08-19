use std::str::FromStr;

use bigdecimal::{BigDecimal, ParseBigDecimalError};

use crate::decimal::{Decimal, DecimalError, ZeroMostSignificantBit};

#[derive(Clone)]
pub struct Xfl {
    inner: Decimal<ZeroMostSignificantBit>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum XflError {
    #[error("invalid byte length; expected: 8; actual: {0}")]
    InvalidByteLength(usize),
    #[error("the first bit must be 0")]
    InvalidXflBit,
    #[error("exponent value out of range: [-96, 80]")]
    ExponentOutOfRange,
    #[error("mantissa value out of range: [(1000000000000000, 9999999999999999]")]
    MantissaOutOfRange,
    #[error(transparent)]
    ParseBigDecimalError(ParseBigDecimalError),
}

impl Xfl {
    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, XflError> {
        Ok(Self {
            inner: Decimal::from_be_byte_slice(bytes)?,
        })
    }

    pub fn enclosing(&self) -> u64 {
        u64::from_be_bytes(self.inner.to_be_bytes())
    }

    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.inner.to_be_bytes()
    }

    pub fn to_le_bytes(&self) -> [u8; 8] {
        self.inner.to_le_bytes()
    }
}

impl std::fmt::Debug for Xfl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.inner {
            Decimal::Zero => write!(f, "<zero>"),
            Decimal::NonZero(value) => {
                write!(
                    f,
                    "{}{} * 10^({})",
                    if value.is_positive { "+" } else { "-" },
                    value.mantissa,
                    value.exponent
                )
            }
        }
    }
}

impl From<&Xfl> for BigDecimal {
    fn from(value: &Xfl) -> Self {
        (&value.inner).into()
    }
}

impl From<Xfl> for BigDecimal {
    fn from(value: Xfl) -> Self {
        (&value.inner).into()
    }
}

impl TryFrom<BigDecimal> for Xfl {
    type Error = XflError;

    fn try_from(value: BigDecimal) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: value.try_into()?,
        })
    }
}

impl FromStr for Xfl {
    type Err = XflError;

    fn from_str(s: &str) -> Result<Self, XflError> {
        Ok(Self {
            inner: Decimal::from_str(s)?,
        })
    }
}

impl From<DecimalError> for XflError {
    fn from(value: DecimalError) -> Self {
        match value {
            DecimalError::InvalidByteLength(inner) => Self::InvalidByteLength(inner),
            DecimalError::InvalidMsb => Self::InvalidXflBit,
            DecimalError::ExponentOutOfRange => Self::ExponentOutOfRange,
            DecimalError::MantissaOutOfRange => Self::MantissaOutOfRange,
            DecimalError::ParseBigDecimalError(inner) => Self::ParseBigDecimalError(inner),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xfl() {
        let cases: Vec<(Result<Xfl, XflError>, &str, u64, &str)> = vec![
            (Xfl::from_str("0.0"), "0", 0, "<zero>"),
            (
                Xfl::from_str("1.0"),
                "1.0",
                6089866696204910592,
                "+1000000000000000 * 10^(-15)",
            ),
            (
                Xfl::from_str("-1.0"),
                "-1.0",
                1478180677777522688,
                "-1000000000000000 * 10^(-15)",
            ),
            (
                Xfl::from_str("3.141592653589793"),
                "3.141592653589793",
                6092008288858500385,
                "+3141592653589793 * 10^(-15)",
            ),
            (
                Xfl::from_str("-3.141592653589793"),
                "-3.141592653589793",
                1480322270431112481,
                "-3141592653589793 * 10^(-15)",
            ),
            (
                Xfl::from_str("-2.001_832_918_266_401e63"),
                "-2.001_832_918_266_401e63",
                2614089616793154081,
                "-2001832918266401 * 10^(48)",
            ),
            (
                Xfl::from_str("-2.001_832_918_266_402e63"),
                "-2.001_832_918_266_402e63",
                2614089616793154082,
                "-2001832918266402 * 10^(48)",
            ),
            (
                Xfl::from_str("6.383472914787617e-70"),
                "6.383472914787617e-70",
                4834242273455959329,
                "+6383472914787617 * 10^(-85)",
            ),
        ];

        for (xfl, expected_str, expected_u64, expected_dbg_string) in cases {
            let xfl_success = xfl.expect("parsing into xfl failed");
            assert_eq!(expected_dbg_string, format!("{:?}", xfl_success));
            assert_eq!(xfl_success.enclosing(), expected_u64);
            assert_eq!(
                Into::<BigDecimal>::into(xfl_success),
                BigDecimal::from_str(expected_str).unwrap()
            );
        }
    }

    #[test]
    fn test_hex() {
        let cases = vec![
            (Xfl::from_str("1.0"), "0080C6A47E8D8354"),
            (Xfl::from_str("-1.0"), "0080C6A47E8D8314"),
            (Xfl::from_str("3.141592653589793"), "216D250A43298B54"),
            (Xfl::from_str("-3.141592653589793"), "216D250A43298B14"),
            (Xfl::from_str("4834242273455959000"), "57AF77BDB72C1159"),
            (
                Xfl::from_str("-2.001_832_918_266_402e63"),
                "2232FE0BA81C4724",
            ),
            (Xfl::from_str("6.383472914787617e-70"), "21ED841BBCAD1643"),
        ];

        for (xfl, expected_flipped_hex_le_string) in cases {
            let xfl_success = xfl.expect("parsing into xfl failed");
            assert_eq!(
                hex::encode_upper(xfl_success.to_le_bytes()),
                expected_flipped_hex_le_string
            );
            let be_bytes = hex::decode(expected_flipped_hex_le_string)
                .expect("hex decoding failed")
                .into_iter()
                .rev()
                .collect::<Vec<u8>>();
            let be_hex_str = hex::encode_upper(be_bytes);
            assert_eq!(
                xfl_success.enclosing(),
                Xfl::from_byte_slice(&hex::decode(be_hex_str).unwrap())
                    .expect("parsing into xfl from hex string failed")
                    .enclosing()
            );
        }
    }
}
