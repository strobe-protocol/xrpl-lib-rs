#![allow(clippy::manual_range_contains)]

use std::str::FromStr;

use bigdecimal::{BigDecimal, ParseBigDecimalError};

use crate::{
    address::{Address, AddressFromSliceError, ADDRESS_LENGTH},
    currency_code::{CurrencyCode, CurrencyCodeError, CURRENCY_CODE_BYTES_LENGTH},
    decimal::{Decimal, DecimalError, OneMostSignificantBit},
};

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
pub struct TokenValue {
    inner: Decimal<OneMostSignificantBit>,
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
        self.inner.to_be_bytes()
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, TokenValueError> {
        Ok(Self {
            inner: Decimal::from_be_byte_slice(bytes)?,
        })
    }
}

impl From<&TokenValue> for BigDecimal {
    fn from(value: &TokenValue) -> Self {
        (&value.inner).into()
    }
}

impl From<TokenValue> for BigDecimal {
    fn from(value: TokenValue) -> Self {
        (&value.inner).into()
    }
}

impl TryFrom<BigDecimal> for TokenValue {
    type Error = TokenValueError;

    fn try_from(value: BigDecimal) -> Result<Self, Self::Error> {
        Ok(Self {
            inner: value.try_into()?,
        })
    }
}

impl FromStr for TokenValue {
    type Err = TokenValueError;

    fn from_str(s: &str) -> Result<Self, TokenValueError> {
        Ok(Self {
            inner: Decimal::from_str(s)?,
        })
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

impl From<DecimalError> for TokenValueError {
    fn from(value: DecimalError) -> Self {
        match value {
            DecimalError::InvalidByteLength(inner) => Self::InvalidByteLength(inner),
            DecimalError::InvalidMsb => Self::InvalidNotXrpBit,
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
