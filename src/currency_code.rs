use std::str::FromStr;

const ALLOWED_ISO_CURRENCY_CHARS: &[u8; 80] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789?!@#$%^&*<>(){}[]|";

const STANDARD_CURRENCY_CODE_LENGTH: usize = 3;
pub(crate) const CURRENCY_CODE_BYTES_LENGTH: usize = 20;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CurrencyCode {
    Standard(StandardCurrencyCode),
    Arbitrary(ArbitraryCurrencyCode),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct StandardCurrencyCode {
    inner: [u8; 3],
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ArbitraryCurrencyCode {
    inner: [u8; CURRENCY_CODE_BYTES_LENGTH],
}

#[derive(Debug, thiserror::Error)]
pub enum CurrencyCodeError {
    #[error("invalid byte length; expected: 20; actual: {0}")]
    InvalidByteLength(usize),
    #[error("reserved bits must be zero for standard currency codes")]
    NonZeroReservedBits,
    #[error(transparent)]
    InvalidStandardCurrencyCode(StandardCurrencyCodeError),
}

#[derive(Debug, thiserror::Error)]
pub enum StandardCurrencyCodeError {
    #[error("the currency code `XRP` is forbidden")]
    Forbidden,
    #[error("invalid ISO currency code char")]
    InvalidChar,
    #[error("input must be 3 chars in length")]
    InvalidLength,
}

#[derive(Debug, thiserror::Error)]
pub enum ArbitraryCurrencyCodeError {
    #[error("prefix for non-standard currency codes cannot be 0x00")]
    InvalidPrefix,
}

impl CurrencyCode {
    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, CurrencyCodeError> {
        if bytes.len() != CURRENCY_CODE_BYTES_LENGTH {
            return Err(CurrencyCodeError::InvalidByteLength(bytes.len()));
        }

        if bytes[0] == 0x00 {
            // Standard currency code
            let reserved_bits_occupied = bytes[1..12]
                .iter()
                .chain(bytes[15..].iter())
                .any(|byte| *byte != 0);
            if reserved_bits_occupied {
                return Err(CurrencyCodeError::NonZeroReservedBits);
            }

            Ok(Self::Standard(StandardCurrencyCode::new(
                // Unwrapping here is safe as the length matches
                bytes[12..15].try_into().unwrap(),
            )?))
        } else {
            // Non-standard currency code

            Ok(Self::Arbitrary(
                ArbitraryCurrencyCode::new(
                    // Unwrapping is safe as we already checked length
                    bytes.try_into().unwrap(),
                )
                // Unwrapping is safe as we already checked prefix
                .unwrap(),
            ))
        }
    }

    pub fn to_bytes(&self) -> [u8; CURRENCY_CODE_BYTES_LENGTH] {
        match self {
            CurrencyCode::Standard(code) => {
                let mut buffer = [0u8; CURRENCY_CODE_BYTES_LENGTH];
                buffer[12..15].copy_from_slice(&code.to_bytes());
                buffer
            }
            CurrencyCode::Arbitrary(code) => code.to_bytes(),
        }
    }
}

impl StandardCurrencyCode {
    pub fn new(chars: [u8; 3]) -> Result<Self, StandardCurrencyCodeError> {
        if &chars == b"XRP" {
            return Err(StandardCurrencyCodeError::Forbidden);
        }

        for c in chars.iter() {
            if !ALLOWED_ISO_CURRENCY_CHARS.contains(c) {
                return Err(StandardCurrencyCodeError::InvalidChar);
            }
        }

        Ok(Self { inner: chars })
    }

    pub fn to_bytes(&self) -> [u8; 3] {
        self.inner
    }
}

impl ArbitraryCurrencyCode {
    pub fn new(
        bytes: [u8; CURRENCY_CODE_BYTES_LENGTH],
    ) -> Result<Self, ArbitraryCurrencyCodeError> {
        if bytes[0] == 0 {
            Err(ArbitraryCurrencyCodeError::InvalidPrefix)
        } else {
            Ok(Self { inner: bytes })
        }
    }

    pub fn to_bytes(&self) -> [u8; CURRENCY_CODE_BYTES_LENGTH] {
        self.inner
    }
}

impl FromStr for StandardCurrencyCode {
    type Err = StandardCurrencyCodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes: [u8; STANDARD_CURRENCY_CODE_LENGTH] = s
            .as_bytes()
            .try_into()
            .map_err(|_| StandardCurrencyCodeError::InvalidLength)?;
        Self::new(bytes)
    }
}

impl ToString for CurrencyCode {
    fn to_string(&self) -> String {
        match self {
            CurrencyCode::Standard(code) => code.to_string(),
            CurrencyCode::Arbitrary(code) => code.to_string(),
        }
    }
}

impl ToString for StandardCurrencyCode {
    fn to_string(&self) -> String {
        format!(
            "{}{}{}",
            self.inner[0] as char, self.inner[1] as char, self.inner[2] as char
        )
    }
}

impl ToString for ArbitraryCurrencyCode {
    fn to_string(&self) -> String {
        hex::encode_upper(self.inner)
    }
}

impl From<StandardCurrencyCode> for CurrencyCode {
    fn from(value: StandardCurrencyCode) -> Self {
        Self::Standard(value)
    }
}

impl From<ArbitraryCurrencyCode> for CurrencyCode {
    fn from(value: ArbitraryCurrencyCode) -> Self {
        Self::Arbitrary(value)
    }
}

impl From<StandardCurrencyCodeError> for CurrencyCodeError {
    fn from(value: StandardCurrencyCodeError) -> Self {
        Self::InvalidStandardCurrencyCode(value)
    }
}
