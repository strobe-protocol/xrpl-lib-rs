use serde::{Deserialize, Serialize};

use crate::base58check;

const ADDRESS_VERSION: u8 = 0;
const ADDRESS_LENGTH: usize = 20;

#[derive(Debug, PartialEq, Eq)]
pub struct Address {
    inner: [u8; ADDRESS_LENGTH],
}

#[derive(Debug, thiserror::Error)]
pub enum AddressFromEncodedError {
    #[error(transparent)]
    DecodeError(base58check::DecodeError),
    #[error("invalid base58check version; expected: 0; actual: {0}")]
    InvalidVersion(u8),
    #[error("invalid payload byte length; expected: 20; actual: {0}")]
    InvalidPayloadLength(usize),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid slice byte length; expected: 20; actual: {0}")]
pub struct AddressFromSliceError(usize);

impl Address {
    pub fn from_byte_array(bytes: [u8; 20]) -> Self {
        Self { inner: bytes }
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, AddressFromSliceError> {
        if bytes.len() == ADDRESS_LENGTH {
            Ok(Self {
                inner: bytes.try_into().unwrap(),
            })
        } else {
            Err(AddressFromSliceError(bytes.len()))
        }
    }

    pub fn from_base58check(encoded: &str) -> Result<Self, AddressFromEncodedError> {
        let decoded = base58check::decode(encoded).map_err(AddressFromEncodedError::DecodeError)?;

        if decoded.version != ADDRESS_VERSION {
            return Err(AddressFromEncodedError::InvalidVersion(decoded.version));
        }

        if decoded.payload.len() != ADDRESS_LENGTH {
            return Err(AddressFromEncodedError::InvalidPayloadLength(
                decoded.payload.len(),
            ));
        }

        Ok(Self {
            // We already checked length so it's fine to unwrap
            inner: decoded.payload.try_into().unwrap(),
        })
    }

    pub fn to_base58check(&self) -> String {
        base58check::encode(ADDRESS_VERSION, &self.inner)
    }

    pub fn to_bytes(&self) -> [u8; 20] {
        self.inner
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base58check())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::from_base58check(&value).map_err(|err| serde::de::Error::custom(format!("{}", err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const ENCODED: &str = "rh17sCvf1XKie2v9gdrZh3oDihyGsgkDdX";
    const BYTES: [u8; 20] = hex!("2a73c099d4b6e693facac67be9dc780043d78b12");

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_address_from_base58check() {
        let address = Address::from_base58check(ENCODED).unwrap();

        assert_eq!(BYTES, address.to_bytes());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_address_to_base58check() {
        let address = Address::from_base58check(ENCODED).unwrap();

        assert_eq!(ENCODED, address.to_base58check());
    }
}
