#![allow(clippy::manual_range_contains)]

use std::str::FromStr;

use bigdecimal::{BigDecimal, ParseBigDecimalError, Zero};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, Signed};

use crate::{
    address::{Address, AddressFromSliceError, ADDRESS_LENGTH},
    currency_code::{CurrencyCode, CurrencyCodeError, CURRENCY_CODE_BYTES_LENGTH},
};

const ZERO_TOKEN_VALUE: [u8; 8] = [0x80, 0, 0, 0, 0, 0, 0, 0];
const NOT_XRP_BIT_MASK: u64 = 0x8000000000000000;
const SIGN_BIT_MASK: u64 = 0x4000000000000000;
const EXPONENT_MASK: u64 = 0x3fc0000000000000;
const MANTISSA_MASK: u64 = 0x003fffffffffffff;

const MIN_MANTISSA: u64 = 1000000000000000;
const MAX_MANTISSA: u64 = 9999999999999999;
const MIN_EXPONENT: i8 = -96;
const MAX_EXPONENT: i8 = 80;

const TOKEN_VALUE_BYTES_LENGTH: usize = 8;
const TOKEN_AMOUNT_BYTES_LENGTH: usize =
    TOKEN_VALUE_BYTES_LENGTH + CURRENCY_CODE_BYTES_LENGTH + ADDRESS_LENGTH;

#[derive(Debug, Clone)]
pub struct TokenAmount {
    pub value: TokenValue,
    pub currency: CurrencyCode,
    pub issuer: Address,
}

#[derive(Debug, Clone)]
pub enum TokenValue {
    Zero,
    NonZero(NonZeroTokenValue),
}

#[derive(Debug, Clone)]
pub struct NonZeroTokenValue {
    is_positive: bool,
    exponent: i8,
    mantissa: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenAmountError {
    #[error("invalid byte length; expected: 48; actual: {0}")]
    InvalidByteLength(usize),
    #[error(transparent)]
    TokenValueError(TokenValueError),
    #[error(transparent)]
    CurrencyCodeError(CurrencyCodeError),
    #[error(transparent)]
    IssuerError(AddressFromSliceError),
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TokenValueError {
    #[error("invalid byte length; expected: 8; actual: {0}")]
    InvalidByteLength(usize),
    #[error("the first bit must be 1")]
    InvalidNotXrpBit,
    #[error("exponent value out of range: [-96, 80]")]
    ExponentOutOfRange,
    #[error("mantissa value out of range: [(1000000000000000, 9999999999999999]")]
    MantissaOutOfRange,
    #[error(transparent)]
    ParseBigDecimalError(ParseBigDecimalError),
}

impl TokenAmount {
    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, TokenAmountError> {
        if bytes.len() == TOKEN_AMOUNT_BYTES_LENGTH {
            let value = TokenValue::from_byte_slice(&bytes[0..8])?;
            let currency = CurrencyCode::from_byte_slice(&bytes[8..28])?;
            let issuer = Address::from_byte_slice(&bytes[28..])?;

            Ok(Self {
                value,
                currency,
                issuer,
            })
        } else {
            Err(TokenAmountError::InvalidByteLength(bytes.len()))
        }
    }

    pub fn to_bytes(&self) -> [u8; TOKEN_AMOUNT_BYTES_LENGTH] {
        let mut buffer = [0u8; TOKEN_AMOUNT_BYTES_LENGTH];
        buffer[0..8].copy_from_slice(&self.value.to_bytes());
        buffer[8..28].copy_from_slice(&self.currency.to_bytes());
        buffer[28..48].copy_from_slice(&self.issuer.to_bytes());
        buffer
    }
}

impl TokenValue {
    pub fn to_bytes(&self) -> [u8; TOKEN_VALUE_BYTES_LENGTH] {
        match self {
            TokenValue::Zero => ZERO_TOKEN_VALUE,
            TokenValue::NonZero(value) => value.to_bytes(),
        }
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, TokenValueError> {
        if bytes.len() != TOKEN_VALUE_BYTES_LENGTH {
            return Err(TokenValueError::InvalidByteLength(bytes.len()));
        }

        if bytes == ZERO_TOKEN_VALUE {
            Ok(Self::Zero)
        } else {
            Ok(Self::NonZero(NonZeroTokenValue::from_byte_slice(bytes)?))
        }
    }
}

impl NonZeroTokenValue {
    pub fn new(is_positive: bool, exponent: i8, mantissa: u64) -> Result<Self, TokenValueError> {
        if exponent < MIN_EXPONENT || exponent > MAX_EXPONENT {
            return Err(TokenValueError::ExponentOutOfRange);
        }

        if mantissa < MIN_MANTISSA || mantissa > MAX_MANTISSA {
            return Err(TokenValueError::MantissaOutOfRange);
        }

        Ok(Self {
            is_positive,
            exponent,
            mantissa,
        })
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, TokenValueError> {
        if bytes.len() != TOKEN_VALUE_BYTES_LENGTH {
            return Err(TokenValueError::InvalidByteLength(bytes.len()));
        }

        // Unwrapping is safe as we already checked length
        let enclosing = u64::from_be_bytes(bytes.try_into().unwrap());

        if enclosing & NOT_XRP_BIT_MASK == 0 {
            return Err(TokenValueError::InvalidNotXrpBit);
        }

        let is_positive = enclosing & SIGN_BIT_MASK > 0;

        let exponent = (enclosing & EXPONENT_MASK) >> 54;
        if exponent < 1 || exponent > 177 {
            return Err(TokenValueError::ExponentOutOfRange);
        }

        let exponent = ((exponent as i16) - 97) as i8;

        let mantissa = enclosing & MANTISSA_MASK;

        Self::new(is_positive, exponent, mantissa)
    }

    pub fn to_bytes(&self) -> [u8; TOKEN_VALUE_BYTES_LENGTH] {
        let mut enclosing = NOT_XRP_BIT_MASK;

        if self.is_positive {
            enclosing |= SIGN_BIT_MASK;
        }

        enclosing |= (((self.exponent as i16) + 97) as u64) << 54;
        enclosing |= self.mantissa;

        enclosing.to_be_bytes()
    }
}

impl TryFrom<BigDecimal> for TokenValue {
    type Error = TokenValueError;

    fn try_from(value: BigDecimal) -> Result<Self, Self::Error> {
        if value.is_zero() {
            return Ok(Self::Zero);
        }

        let value = value.normalized();

        let min_mantissa = BigInt::from_u64(MIN_MANTISSA).unwrap();
        let max_mantissa = BigInt::from_u64(MAX_MANTISSA).unwrap();

        let (mantissa, exp) = value.as_bigint_and_exponent();

        // We interpret exponent differently
        let mut exponent = -exp;

        let (mut mantissa, is_positive) = if mantissa.is_negative() {
            // For negative numbers, BigDecimal gives mantissa as negative
            (-mantissa, false)
        } else {
            (mantissa, true)
        };

        // If `mantissa` is too small we bring it into range
        // TODO: possible to change algo to do this in O(1)?
        while mantissa < min_mantissa {
            mantissa *= 10;
            exponent -= 1;
        }

        // If `mantissa` is too big, we try to scale it down without losing precision. If we have
        // to lose precision, it means `mantissa` is out of range.
        // TODO: possible to change algo to do this in O(1)?
        while mantissa > max_mantissa {
            let adjusted_mantissa = &mantissa / 10;
            if &adjusted_mantissa * 10 != mantissa {
                return Err(TokenValueError::MantissaOutOfRange);
            }

            mantissa = adjusted_mantissa;
            exponent += 1;
        }

        // Mantissa is already in range so we only need to check exponent.
        if exponent < (MIN_EXPONENT as i64) || exponent > (MAX_EXPONENT as i64) {
            return Err(TokenValueError::ExponentOutOfRange);
        }

        let (_, mantissa) = mantissa.to_u64_digits();

        // We already checked that mantissa is in range
        debug_assert_eq!(mantissa.len(), 1);
        let mantissa = mantissa[0];

        Ok(Self::NonZero(NonZeroTokenValue::new(
            is_positive,
            exponent as i8,
            mantissa,
        )?))
    }
}

impl FromStr for TokenValue {
    type Err = TokenValueError;

    fn from_str(s: &str) -> Result<Self, TokenValueError> {
        let decimal = BigDecimal::from_str(s).map_err(TokenValueError::ParseBigDecimalError)?;
        decimal.try_into()
    }
}

impl From<TokenValueError> for TokenAmountError {
    fn from(value: TokenValueError) -> Self {
        Self::TokenValueError(value)
    }
}

impl From<CurrencyCodeError> for TokenAmountError {
    fn from(value: CurrencyCodeError) -> Self {
        Self::CurrencyCodeError(value)
    }
}

impl From<AddressFromSliceError> for TokenAmountError {
    fn from(value: AddressFromSliceError) -> Self {
        Self::IssuerError(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_normal_token_value() {
        let decimal = BigDecimal::from_str("52.121").unwrap();
        let token_value: TokenValue = decimal
            .try_into()
            .expect("failed to parse token value from bigdecimal");

        assert_eq!(
            "D4D284609908A800",
            hex::encode_upper(token_value.to_bytes())
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_precision_of_17() {
        let decimal = BigDecimal::from_str("1111111111111111.1").unwrap();

        match TryInto::<TokenValue>::try_into(decimal) {
            Ok(_) => panic!("should error on precision out of range"),
            Err(TokenValueError::MantissaOutOfRange) => {}
            Err(_) => panic!("unexpected error"),
        };
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_precision_of_16() {
        let decimal = BigDecimal::from_str("11111111111111.1").unwrap();

        let token_value: TokenValue = decimal
            .try_into()
            .expect("failed to parse token value from bigdecimal");
        assert_eq!(
            "D7C3F28CB71571C6",
            hex::encode_upper(token_value.to_bytes())
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_exponent_of_81() {
        let decimal = BigDecimal::from_str(
            "9999999999999999\
            000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();

        match TryInto::<TokenValue>::try_into(decimal) {
            Ok(_) => panic!("should error on overflow"),
            Err(TokenValueError::ExponentOutOfRange) => {}
            Err(_) => panic!("unexpected error"),
        };
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_exponent_of_80() {
        let decimal = BigDecimal::from_str(
            "9999999999999999\
            00000000000000000000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let token_value: TokenValue = decimal
            .try_into()
            .expect("failed to parse token value from bigdecimal");
        assert_eq!(
            "EC6386F26FC0FFFF",
            hex::encode_upper(token_value.to_bytes())
        );
    }
}
