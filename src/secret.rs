use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::{base58check, crypto::PrivateKey};

const SEED_VERSION: u8 = 33;
const SEED_LENGTH: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub struct Secret {
    inner: [u8; SEED_LENGTH],
}

#[derive(Debug, thiserror::Error)]
pub enum SecretFromEncodedError {
    #[error(transparent)]
    DecodeError(base58check::DecodeError),
    #[error("invalid base58check version; expected: 33; actual: {0}")]
    InvalidVersion(u8),
    #[error("invalid payload byte length; expected: 16; actual: {0}")]
    InvalidPayloadLength(usize),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid slice byte length; expected: 16; actual: {0}")]
pub struct SecretFromSliceError(usize);

impl Secret {
    pub fn from_random() -> Self {
        let mut rng = StdRng::from_entropy();
        let mut buffer = [0u8; SEED_LENGTH];
        rng.fill(&mut buffer);

        Self::from_byte_array(buffer)
    }

    pub fn from_byte_array(bytes: [u8; SEED_LENGTH]) -> Self {
        Self { inner: bytes }
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, SecretFromSliceError> {
        if bytes.len() == SEED_LENGTH {
            Ok(Self {
                inner: bytes.try_into().unwrap(),
            })
        } else {
            Err(SecretFromSliceError(bytes.len()))
        }
    }

    pub fn from_base58check(encoded: &str) -> Result<Self, SecretFromEncodedError> {
        let decoded = base58check::decode(encoded).map_err(SecretFromEncodedError::DecodeError)?;

        if decoded.version != SEED_VERSION {
            return Err(SecretFromEncodedError::InvalidVersion(decoded.version));
        }

        if decoded.payload.len() != SEED_LENGTH {
            return Err(SecretFromEncodedError::InvalidPayloadLength(
                decoded.payload.len(),
            ));
        }

        Ok(Self {
            // We already checked length so it's fine to unwrap
            inner: decoded.payload.try_into().unwrap(),
        })
    }

    pub fn private_key(&self) -> PrivateKey {
        self.into()
    }

    pub fn to_base58check(&self) -> String {
        base58check::encode(SEED_VERSION, &self.inner)
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        self.inner
    }
}

impl Serialize for Secret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base58check())
    }
}

impl<'de> Deserialize<'de> for Secret {
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

    const ENCODED: &str = "spvyv3vG6GBG9sA6o4on8YDpxp9ZZ";
    const BYTES: [u8; 16] = hex!("10ee423d1d21682fa4cbb6297f6f6fec");

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_secret_from_base58check() {
        let secret = Secret::from_base58check(ENCODED).unwrap();

        assert_eq!(BYTES, secret.to_bytes());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_secret_to_base58check() {
        let secret = Secret::from_base58check(ENCODED).unwrap();

        assert_eq!(ENCODED, secret.to_base58check());
    }
}
