use std::{ops::Mul, str::FromStr};

use bigdecimal::{BigDecimal, ParseBigDecimalError, Zero};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, Signed};
use regex::Regex;

use crate::address::{Address, AddressFromEncodedError, ADDRESS_LENGTH};

const NOT_XRP_ZERO: u64 = 0x8000000000000000;
const POS_SIGN_BIT_MASK: u64 = 0x4000000000000000;
const MANTISSA_DIGITS_MASK: u64 = 0x1FFFFFFFFFFFFFF;
const MIN_MANTISSA: u64 = u64::pow(10, 15);
const MAX_MANTISSA: u64 = u64::pow(10, 16) - 1;
const MIN_TOKEN_VALUE_EXPONENT: i64 = -96;
const MAX_TOKEN_VALUE_EXPONENT: i64 = 80;
const MAX_TOKEN_VALUE_PRECISION: u64 = 16;

const XRP_SYMBOL: &str = "XRP";
const XRP_HEX: &str = "0000000000000000000000005852500000000000";
const ISO_REGEX: &str = r"^[A-Z0-9a-z?!@#$%^&*(){}[\]|]]{3}$";
const HEX_REGEX: &str = r"^[A-F0-9]{40}$";

const XRP_AMOUNT_BYTES_LENGTH: usize = 8;
const TOKEN_VALUE_BYTES_LENGTH: usize = 8;
const CURRENCY_CODE_BYTES_LENGTH: usize = 20;
const TOKEN_AMOUNT_BYTES_LENGTH: usize = 48;

const MAX_DROPS: u64 = 100000000000000000;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseTokenValueError {
    #[error("invalid decimal scale; expected within the range of i32; actual: {0}")]
    InvalidScale(u32),
    #[error("exponent overflow; maximum exponent: 80; actual: {0}")]
    ExponentOverflow(i64),
    #[error("exponent underflow; minimum exponent: -96; actual: {0}")]
    ExponentUnderflow(i64),
    #[error("mantissa underflow; minimum mantissa: 10^(15); actual: {0}")]
    MantissaUnderflow(BigInt),
    #[error("mantissa overflow; maximum mantissa: 10^(16) - 1; actual: {0}")]
    MantissaOverflow(BigInt),
    #[error("precision out of range; maximum significant digits: 16; maximum exponent: 80; minimum exponent: -96; actual significant digits: {precision}; actual exponent: {exponent}")]
    PrecisionOutOfRange { precision: u64, exponent: i64 },
    #[error("invalid decimal format; the decimal number itself multiplied by 1 to the power of its exponent must be without a decimal place. actual decimal: {decimal}; actual exponent: {exponent};")]
    DecimalPlaceFound { decimal: String, exponent: i64 },
    #[error(transparent)]
    ParseBigDecimalError(ParseBigDecimalError),
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ParseCurrencyCodeError {
    #[error("invalid string representation of currency code; actual: {0}; expected: any valid currency code of 160 bits")]
    InvalidCurrencyCode(String),
    #[error("invalid curreny code representing XRP; expected: any other valid currency code of 160 bits")]
    DisallowedXrpCode,
    #[error(transparent)]
    FromHexError(hex::FromHexError),
    #[error(transparent)]
    InvalidBytesLength(InvalidBytesLength),
}

#[derive(Debug)]
pub enum TokenAmountFromStringsError {
    ParseCurrencyCodeError(ParseCurrencyCodeError),
    ParseBigDecimalError(ParseBigDecimalError),
    ParseTokenValueError(ParseTokenValueError),
    AddressFromEncodedError(AddressFromEncodedError),
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum XrpAmountFromDropsError {
    #[error(
        "amount of drops is out of range; expected: within the range of 0 to 100000000000000000"
    )]
    AmountOutOfRange,
}

#[derive(Debug, thiserror::Error)]
pub enum TokenAmountFromBytesError {
    #[error(transparent)]
    InvalidPartBytesLength(InvalidBytesLength),
    #[error("invalid token amount length; expected: 8 or 48; actual: {0}")]
    InvalidTokenAmountBytesLength(usize),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("invalid slice byte length; expected: {0}; actual: {0}")]
pub struct InvalidBytesLength(usize, usize);

#[derive(Debug, Clone)]
pub struct TokenValue {
    inner: [u8; TOKEN_VALUE_BYTES_LENGTH],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CurrencyCode {
    inner: [u8; CURRENCY_CODE_BYTES_LENGTH],
}

#[derive(Debug, Clone)]
pub struct TokenAmount {
    pub value: TokenValue,
    pub currency: CurrencyCode,
    pub issuer: Address,
}

#[derive(Debug, Clone, Copy)]
pub struct XrpAmount(u64);

#[derive(Debug, Clone)]
pub enum Amount {
    Token(TokenAmount),
    Xrp(XrpAmount),
}

impl TokenValue {
    pub fn to_bytes(&self) -> [u8; TOKEN_VALUE_BYTES_LENGTH] {
        self.inner
    }

    pub fn from_byte_array(bytes: [u8; TOKEN_VALUE_BYTES_LENGTH]) -> Self {
        Self { inner: bytes }
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, InvalidBytesLength> {
        if bytes.len() == TOKEN_VALUE_BYTES_LENGTH {
            Ok(Self {
                inner: bytes.try_into().unwrap(),
            })
        } else {
            Err(InvalidBytesLength(TOKEN_VALUE_BYTES_LENGTH, bytes.len()))
        }
    }

    pub fn from_bigdecimal(decimal: BigDecimal) -> Result<Self, ParseTokenValueError> {
        Self::verify_token_amount_value(&decimal)?;
        let normalized_decimal = decimal.normalized();

        let min_mantissa = BigInt::from_u64(MIN_MANTISSA).unwrap();
        let max_mantissa = BigInt::from_u64(MAX_MANTISSA).unwrap();

        if normalized_decimal.is_zero() {
            return Ok(Self {
                inner: (NOT_XRP_ZERO).to_be_bytes(),
            });
        };

        let (mut mantissa, mut exp) = normalized_decimal.as_bigint_and_exponent();

        if !normalized_decimal.is_positive() {
            // for negative numbers, BigDecimal gives mantissa as negative
            mantissa = -mantissa;
        }

        exp = -exp;

        // decrease exponent until mantissa is in range
        while mantissa < min_mantissa && exp > MIN_TOKEN_VALUE_EXPONENT {
            mantissa *= 10;
            exp -= 1;
        }

        // decrease mantissa until exponent is in range
        while mantissa > max_mantissa {
            if exp >= MAX_TOKEN_VALUE_EXPONENT {
                return Err(ParseTokenValueError::ExponentOverflow(exp));
            } else {
                mantissa /= 10;
                exp += 1;
            }
        }

        // For very small or big numbers, it is still possible that
        // exponent or mantissa is too small or big to be represented
        if exp < MIN_TOKEN_VALUE_EXPONENT {
            return Err(ParseTokenValueError::ExponentUnderflow(exp));
        } else if mantissa < min_mantissa {
            return Err(ParseTokenValueError::MantissaUnderflow(mantissa));
        } else if exp > MAX_TOKEN_VALUE_EXPONENT {
            return Err(ParseTokenValueError::ExponentOverflow(exp));
        } else if mantissa > max_mantissa {
            return Err(ParseTokenValueError::MantissaOverflow(mantissa));
        }

        let mut serialized = NOT_XRP_ZERO;

        // Unlike standard two's complement integers, 1 indicates positive in the XRP Ledger format,
        // and 0 indicates negative
        if normalized_decimal.is_positive() {
            serialized |= POS_SIGN_BIT_MASK;
        };

        // When serializing, we add 97 to the exponent to make it possible to serialize as an
        // unsigned integer. Thus, a serialized value of 1 indicates an exponent of -96, a
        // serialized value of 177 indicates an exponent of 80, and so on. Rightmost 54 bits
        // are significant digits
        //
        // exp + 97 is always above 0 and equal to or less than 177
        serialized |= u64::try_from(exp + 97).unwrap() << 54;

        let (_, mantissa_u64_digits) = mantissa.to_u64_digits();

        // Mantissa is always under or equal to 54 bits, so length should be always equal to 1
        if mantissa_u64_digits.len() != 1 {
            return Err(ParseTokenValueError::MantissaOverflow(mantissa));
        }

        let mantissa_u64_digit = mantissa_u64_digits[0];

        if mantissa_u64_digit & MANTISSA_DIGITS_MASK != mantissa_u64_digit {
            return Err(ParseTokenValueError::MantissaOverflow(mantissa));
        }

        serialized |= mantissa_u64_digit;

        Ok(Self {
            inner: serialized.to_be_bytes(),
        })
    }

    fn verify_no_decimal(decimal: &BigDecimal) -> Result<(), ParseTokenValueError> {
        let (_, exponent) = decimal.as_bigint_and_exponent();
        let exponent_with_base_of_1: BigDecimal = format!("1e{}", exponent).parse().unwrap();
        let multiplied_by_exponent = decimal.mul(exponent_with_base_of_1);

        if !multiplied_by_exponent.is_integer() {
            return Err(ParseTokenValueError::DecimalPlaceFound {
                decimal: decimal.to_string(),
                exponent,
            });
        }

        Ok(())
    }

    fn verify_token_amount_value(decimal: &BigDecimal) -> Result<(), ParseTokenValueError> {
        let normalized_decimal = decimal.normalized();

        if normalized_decimal.is_zero() {
            return Ok(());
        };

        let precision = normalized_decimal.digits();
        let (_, mut exp) = normalized_decimal.as_bigint_and_exponent();
        exp = -exp;

        if precision > MAX_TOKEN_VALUE_PRECISION
            || !(MIN_TOKEN_VALUE_EXPONENT..=MAX_TOKEN_VALUE_EXPONENT).contains(&exp)
        {
            return Err(ParseTokenValueError::PrecisionOutOfRange {
                precision,
                exponent: exp,
            });
        }

        Self::verify_no_decimal(decimal)?;

        Ok(())
    }
}

impl CurrencyCode {
    pub fn to_bytes(&self) -> [u8; CURRENCY_CODE_BYTES_LENGTH] {
        self.inner
    }

    pub fn from_byte_array(bytes: [u8; CURRENCY_CODE_BYTES_LENGTH]) -> Self {
        Self { inner: bytes }
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, InvalidBytesLength> {
        let buffer: [u8; CURRENCY_CODE_BYTES_LENGTH] = bytes
            .try_into()
            .map_err(|_| InvalidBytesLength(CURRENCY_CODE_BYTES_LENGTH, bytes.len()))?;
        Ok(Self { inner: buffer })
    }

    fn is_valid_hex_str(maybe_valid_hex_str: &str) -> Result<(), ParseCurrencyCodeError> {
        let hex_regex = Regex::new(HEX_REGEX).unwrap();
        let xrp_hex_regex = Regex::new(XRP_HEX).unwrap();
        if xrp_hex_regex.is_match(maybe_valid_hex_str) {
            Err(ParseCurrencyCodeError::DisallowedXrpCode)
        } else if hex_regex.is_match(maybe_valid_hex_str) {
            return Ok(());
        } else {
            return Err(ParseCurrencyCodeError::InvalidCurrencyCode(
                maybe_valid_hex_str.to_string(),
            ));
        }
    }

    fn is_iso_code(value: &str) -> bool {
        let iso_regex = Regex::new(ISO_REGEX).unwrap();
        iso_regex.is_match(value)
    }

    fn iso_to_bytes(
        maybe_iso_code: &str,
    ) -> Result<[u8; CURRENCY_CODE_BYTES_LENGTH], ParseCurrencyCodeError> {
        if !Self::is_iso_code(maybe_iso_code) {
            Err(ParseCurrencyCodeError::InvalidCurrencyCode(
                maybe_iso_code.to_string(),
            ))
        } else if maybe_iso_code == XRP_SYMBOL {
            Ok([0u8; CURRENCY_CODE_BYTES_LENGTH])
        } else {
            // String must be 3 characters long, checked by regex already
            let iso_code: [u8; 3] = maybe_iso_code.as_bytes().try_into().unwrap();

            let mut result = [0u8; CURRENCY_CODE_BYTES_LENGTH];
            result[12..15].clone_from_slice(&iso_code);
            Ok(result)
        }
    }
}

impl TokenAmount {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.extend_from_slice(&self.value.to_bytes());
        buffer.extend_from_slice(&self.currency.to_bytes());
        buffer.extend_from_slice(&self.issuer.to_bytes());
        buffer
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, InvalidBytesLength> {
        if bytes.len() == TOKEN_AMOUNT_BYTES_LENGTH {
            let value = TokenValue::from_byte_slice(&bytes[0..8])?;
            let currency = CurrencyCode::from_byte_slice(&bytes[8..28])?;
            let issuer = Address::from_byte_slice(&bytes[28..])
                .map_err(|_| InvalidBytesLength(ADDRESS_LENGTH, bytes[28..].len()))?;

            Ok(Self {
                value,
                currency,
                issuer,
            })
        } else {
            Err(InvalidBytesLength(TOKEN_AMOUNT_BYTES_LENGTH, bytes.len()))
        }
    }

    pub fn from_strings(
        value: &str,
        currency: &str,
        issuer: &str,
    ) -> Result<Self, TokenAmountFromStringsError> {
        let bigdecimal_value = BigDecimal::from_str(value)
            .map_err(TokenAmountFromStringsError::ParseBigDecimalError)?;
        let value = TokenValue::from_bigdecimal(bigdecimal_value)
            .map_err(TokenAmountFromStringsError::ParseTokenValueError)?;
        let currency = CurrencyCode::from_str(currency)
            .map_err(TokenAmountFromStringsError::ParseCurrencyCodeError)?;
        let issuer = Address::from_base58check(issuer)
            .map_err(TokenAmountFromStringsError::AddressFromEncodedError)?;

        Ok(TokenAmount {
            value,
            currency,
            issuer,
        })
    }
}

impl XrpAmount {
    pub fn to_bytes(&self) -> Vec<u8> {
        let xrp_amount = self.to_u64() | POS_SIGN_BIT_MASK;
        xrp_amount.to_be_bytes().to_vec()
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, InvalidBytesLength> {
        let buffer: [u8; XRP_AMOUNT_BYTES_LENGTH] = bytes
            .try_into()
            .map_err(|_| InvalidBytesLength(XRP_AMOUNT_BYTES_LENGTH, bytes.len()))?;
        let xrp_amount = u64::from_be_bytes(buffer);

        Ok(Self(xrp_amount))
    }

    pub fn to_u64(self) -> u64 {
        self.0
    }

    pub fn from_drops(drops: u64) -> Result<Self, XrpAmountFromDropsError> {
        if drops > MAX_DROPS {
            return Err(XrpAmountFromDropsError::AmountOutOfRange);
        }
        Ok(Self(drops))
    }
}

impl Amount {
    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, TokenAmountFromBytesError> {
        if bytes.len() == XRP_AMOUNT_BYTES_LENGTH {
            Ok(Amount::Xrp(XrpAmount::from_byte_slice(bytes).unwrap()))
        } else if bytes.len() == TOKEN_AMOUNT_BYTES_LENGTH {
            Ok(Amount::Token(TokenAmount::from_byte_slice(bytes).unwrap()))
        } else {
            Err(TokenAmountFromBytesError::InvalidTokenAmountBytesLength(
                bytes.len(),
            ))
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Amount::Xrp(amount) => amount.to_bytes(),
            Amount::Token(amount) => amount.to_bytes(),
        }
    }

    pub fn from_drops(drops: u64) -> Result<Self, XrpAmountFromDropsError> {
        Ok(Self::Xrp(XrpAmount::from_drops(drops)?))
    }

    pub fn from_strings(
        value: &str,
        currency: &str,
        issuer: &str,
    ) -> Result<Self, TokenAmountFromStringsError> {
        Ok(Amount::Token(TokenAmount::from_strings(
            value, currency, issuer,
        )?))
    }
}

impl FromStr for TokenValue {
    type Err = ParseTokenValueError;

    fn from_str(string: &str) -> Result<Self, ParseTokenValueError> {
        let decimal =
            BigDecimal::from_str(string).map_err(ParseTokenValueError::ParseBigDecimalError)?;
        Self::from_bigdecimal(decimal)
    }
}

impl FromStr for CurrencyCode {
    type Err = ParseCurrencyCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if Self::is_iso_code(s) {
            let inner = Self::iso_to_bytes(s)?;
            return Ok(Self { inner });
        }

        Self::is_valid_hex_str(s)?;

        let inner: [u8; CURRENCY_CODE_BYTES_LENGTH] = match hex::decode(s)
            .map_err(ParseCurrencyCodeError::FromHexError)?
            .try_into()
        {
            Ok(v) => v,
            Err(_) => {
                let bytes_length = (s.len() as f64 / 2.0).ceil() as usize;
                return Err(ParseCurrencyCodeError::InvalidBytesLength(
                    InvalidBytesLength(CURRENCY_CODE_BYTES_LENGTH, bytes_length),
                ));
            }
        };

        Ok(Self { inner })
    }
}

impl ToString for CurrencyCode {
    fn to_string(&self) -> String {
        let buffer = self.inner;

        if buffer == [0u8; CURRENCY_CODE_BYTES_LENGTH] {
            XRP_SYMBOL.to_string()
        } else if buffer.starts_with(&[0u8; 1]) {
            let iso_code = buffer[12..15].to_vec();
            String::from_utf8(iso_code).unwrap()
        } else {
            hex::encode_upper(buffer)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bigdecimal::BigDecimal;
    use hex::encode_upper;

    use super::*;

    const USD_HEX_CODE: &str = "0000000000000000000000005553440000000000";
    const NONSTANDARD_HEX_CODE: &str = "015841551A748AD2C1F76FF6ECB0CCCD00000000";
    const NATIVE_HEX_CODE: &str = "0000000000000000000000000000000000000000";
    const USD_ISO: &str = "USD";

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_normal_token_value() {
        let decimal = BigDecimal::from_str("52.121").unwrap();
        let token_value = TokenValue::from_bigdecimal(decimal)
            .expect("failed to parse token value from bigdecimal");

        assert_eq!("D4D284609908A800", encode_upper(token_value.to_bytes()));
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_in_range_xrp() {
        let xrp_amount = XrpAmount::from_drops(111).expect("failed to parse xrp from drops");

        assert_eq!(xrp_amount.0, 111);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_out_of_range_xrp() {
        assert_eq!(
            XrpAmount::from_drops(MAX_DROPS + 1).err(),
            Some(XrpAmountFromDropsError::AmountOutOfRange)
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_precision_of_17() {
        let decimal = BigDecimal::from_str("1111111111111111.1").unwrap();

        match TokenValue::from_bigdecimal(decimal) {
            Ok(_) => panic!("should error on precision out of range"),
            Err(err) => {
                assert_eq!(
                    ParseTokenValueError::PrecisionOutOfRange {
                        precision: 17,
                        exponent: -1
                    },
                    err
                );
            }
        };
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_precision_of_16() {
        let decimal = BigDecimal::from_str("11111111111111.1").unwrap();

        let token_value = TokenValue::from_bigdecimal(decimal)
            .expect("failed to parse token value from bigdecimal");
        assert_eq!(
            "D7C3F28CB71571C6",
            hex::encode_upper(token_value.to_bytes())
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_exponent_of_81() {
        let decimal = BigDecimal::from_str("9999999999999999000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();

        match TokenValue::from_bigdecimal(decimal) {
            Ok(_) => panic!("should error on overflow"),
            Err(err) => {
                assert_eq!(
                    ParseTokenValueError::PrecisionOutOfRange {
                        precision: 16,
                        exponent: 81
                    },
                    err
                );
            }
        };
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_exponent_of_80() {
        let decimal = BigDecimal::from_str
        ("999999999999999900000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap();
        let token_value = TokenValue::from_bigdecimal(decimal)
            .expect("failed to parse token value from bigdecimal");
        assert_eq!(
            "EC6386F26FC0FFFF",
            hex::encode_upper(token_value.to_bytes())
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_currency_code() {
        let from_hex_xrp = CurrencyCode::from_str(NATIVE_HEX_CODE).unwrap();
        let from_hex_ic = CurrencyCode::from_str(USD_HEX_CODE).unwrap();
        let from_iso_xrp = CurrencyCode::from_str(XRP_SYMBOL).unwrap();
        let from_iso_ic = CurrencyCode::from_str(USD_ISO).unwrap();
        let from_ns = CurrencyCode::from_str(NONSTANDARD_HEX_CODE).unwrap();

        assert_eq!(XRP_SYMBOL, from_hex_xrp.to_string());
        assert_eq!(USD_ISO, from_hex_ic.to_string());
        assert_eq!(NATIVE_HEX_CODE, hex::encode_upper(from_iso_xrp.inner));
        assert_eq!(USD_HEX_CODE, hex::encode_upper(from_iso_ic.inner));
        assert_eq!(NONSTANDARD_HEX_CODE, hex::encode_upper(from_ns.inner));
    }
}
