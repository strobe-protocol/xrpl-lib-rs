#![allow(clippy::manual_range_contains)]

use std::{marker::PhantomData, str::FromStr};

use bigdecimal::{BigDecimal, ParseBigDecimalError};
use num_bigint::BigInt;
use num_traits::{FromPrimitive, Signed, Zero};

const ZERO_WITH_ONE_MSB: [u8; 8] = [0x80, 0, 0, 0, 0, 0, 0, 0];
const ZERO_WITH_ZERO_MSB: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0];

const MSB_MASK: u64 = 0x8000000000000000;
const SIGN_BIT_MASK: u64 = 0x4000000000000000;
const EXPONENT_MASK: u64 = 0x3fc0000000000000;
const MANTISSA_MASK: u64 = 0x003fffffffffffff;

const MIN_MANTISSA: u64 = 1000000000000000;
const MAX_MANTISSA: u64 = 9999999999999999;
const MIN_EXPONENT: i8 = -96;
const MAX_EXPONENT: i8 = 80;

const DECIMAL_BYTES_LENGTH: usize = 8;

/// Common backend for decimal-based types.
#[derive(Debug, Clone)]
pub(crate) enum Decimal<MSB> {
    Zero,
    NonZero(NonZeroDecimal<MSB>),
}

#[derive(Debug, Clone)]
pub(crate) struct NonZeroDecimal<MSB> {
    is_positive: bool,
    exponent: i8,
    mantissa: u64,
    msb: PhantomData<MSB>,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub(crate) enum DecimalError {
    #[error("invalid byte length; expected: 8; actual: {0}")]
    InvalidByteLength(usize),
    #[error("unexcepted value for the most significant bit")]
    InvalidMsb,
    #[error("exponent value out of range: [-96, 80]")]
    ExponentOutOfRange,
    #[error("mantissa value out of range: [(1000000000000000, 9999999999999999]")]
    MantissaOutOfRange,
    #[allow(clippy::enum_variant_names)]
    #[error(transparent)]
    ParseBigDecimalError(ParseBigDecimalError),
}

pub(crate) trait MostSignificantBit {
    fn is_one() -> bool;
}

#[derive(Debug, Clone)]
pub(crate) struct OneMostSignificantBit;

impl MostSignificantBit for OneMostSignificantBit {
    fn is_one() -> bool {
        true
    }
}

impl<MSB> Decimal<MSB>
where
    MSB: MostSignificantBit,
{
    pub fn to_bytes(&self) -> [u8; DECIMAL_BYTES_LENGTH] {
        match self {
            Self::Zero => {
                if MSB::is_one() {
                    ZERO_WITH_ONE_MSB
                } else {
                    ZERO_WITH_ZERO_MSB
                }
            }
            Self::NonZero(value) => value.to_bytes(),
        }
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, DecimalError> {
        if bytes.len() != DECIMAL_BYTES_LENGTH {
            return Err(DecimalError::InvalidByteLength(bytes.len()));
        }

        if bytes
            == if MSB::is_one() {
                ZERO_WITH_ONE_MSB
            } else {
                ZERO_WITH_ZERO_MSB
            }
        {
            Ok(Self::Zero)
        } else {
            Ok(Self::NonZero(NonZeroDecimal::from_byte_slice(bytes)?))
        }
    }
}

impl<MSB> NonZeroDecimal<MSB>
where
    MSB: MostSignificantBit,
{
    pub fn new(is_positive: bool, exponent: i8, mantissa: u64) -> Result<Self, DecimalError> {
        if exponent < MIN_EXPONENT || exponent > MAX_EXPONENT {
            return Err(DecimalError::ExponentOutOfRange);
        }

        if mantissa < MIN_MANTISSA || mantissa > MAX_MANTISSA {
            return Err(DecimalError::MantissaOutOfRange);
        }

        Ok(Self {
            is_positive,
            exponent,
            mantissa,
            msb: PhantomData,
        })
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, DecimalError> {
        if bytes.len() != DECIMAL_BYTES_LENGTH {
            return Err(DecimalError::InvalidByteLength(bytes.len()));
        }

        // Unwrapping is safe as we already checked length
        let enclosing = u64::from_be_bytes(bytes.try_into().unwrap());

        if (enclosing & MSB_MASK > 0) != MSB::is_one() {
            return Err(DecimalError::InvalidMsb);
        }

        let is_positive = enclosing & SIGN_BIT_MASK > 0;

        let exponent = (enclosing & EXPONENT_MASK) >> 54;
        if exponent < 1 || exponent > 177 {
            return Err(DecimalError::ExponentOutOfRange);
        }

        let exponent = ((exponent as i16) - 97) as i8;

        let mantissa = enclosing & MANTISSA_MASK;

        Self::new(is_positive, exponent, mantissa)
    }

    pub fn to_bytes(&self) -> [u8; DECIMAL_BYTES_LENGTH] {
        let mut enclosing = if MSB::is_one() { MSB_MASK } else { 0 };

        if self.is_positive {
            enclosing |= SIGN_BIT_MASK;
        }

        enclosing |= (((self.exponent as i16) + 97) as u64) << 54;
        enclosing |= self.mantissa;

        enclosing.to_be_bytes()
    }
}

impl<MSB> From<&Decimal<MSB>> for BigDecimal {
    fn from(value: &Decimal<MSB>) -> Self {
        match value {
            Decimal::Zero => Self::zero(),
            Decimal::NonZero(value) => {
                // This function always returns `Some`.
                let digits = BigInt::from_u64(value.mantissa).unwrap();
                let digits = if value.is_positive { digits } else { -digits };

                let decimal = Self::new(digits, -value.exponent as i64);
                decimal.normalized()
            }
        }
    }
}

impl<MSB> From<Decimal<MSB>> for BigDecimal {
    fn from(value: Decimal<MSB>) -> Self {
        (&value).into()
    }
}

impl<MSB> TryFrom<BigDecimal> for Decimal<MSB>
where
    MSB: MostSignificantBit,
{
    type Error = DecimalError;

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
                return Err(DecimalError::MantissaOutOfRange);
            }

            mantissa = adjusted_mantissa;
            exponent += 1;
        }

        // Mantissa is already in range so we only need to check exponent.
        if exponent < (MIN_EXPONENT as i64) || exponent > (MAX_EXPONENT as i64) {
            return Err(DecimalError::ExponentOutOfRange);
        }

        let (_, mantissa) = mantissa.to_u64_digits();

        // We already checked that mantissa is in range
        debug_assert_eq!(mantissa.len(), 1);
        let mantissa = mantissa[0];

        Ok(Self::NonZero(NonZeroDecimal::new(
            is_positive,
            exponent as i8,
            mantissa,
        )?))
    }
}

impl<MSB> FromStr for Decimal<MSB>
where
    MSB: MostSignificantBit,
{
    type Err = DecimalError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let decimal = BigDecimal::from_str(s).map_err(DecimalError::ParseBigDecimalError)?;
        decimal.try_into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bigdecimal_round_trip() {
        for decimal_str in ["0", "0.00", "0.00010", "1.23", "12345678.87654321"].into_iter() {
            let parsed_big_decimal: BigDecimal = decimal_str.parse().unwrap();
            let decimal: Decimal<OneMostSignificantBit> =
                parsed_big_decimal.clone().try_into().unwrap();
            let converted_big_decimal: BigDecimal = decimal.into();

            assert_eq!(parsed_big_decimal, converted_big_decimal);
        }
    }
}
