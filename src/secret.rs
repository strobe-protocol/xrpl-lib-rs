use rand::{rngs::StdRng, Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::{base58check, crypto::PrivateKey};

const SEED_LENGTH: usize = 16;
const WITH_SECP256K1_VERSION_SEED_LENGTH: usize = 17;
const WITH_ED25519_VERSION_SEED_LENGTH: usize = 19;

const SECP256K1_SEED_VERSION: [u8; 1] = [33];
const ED25519_SEED_VERSION: [u8; 3] = [0x01, 0xe1, 0x4b];

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Curve {
    Ed25519,
    Secp256k1,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Secret {
    pub curve: Curve,
    inner: [u8; SEED_LENGTH],
}

#[derive(Debug, thiserror::Error)]
pub enum SecretFromEncodedError {
    #[error(transparent)]
    DecodeError(base58check::DecodeError),
    #[error("invalid base58check version; expected: {0:?}; actual: {0:?}")]
    InvalidVersion(Vec<u8>, Vec<u8>),
    #[error("invalid payload byte length; expected: 16; actual: {0}")]
    InvalidPayloadLength(usize),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid slice byte length; expected: {0}; actual: {0}")]
pub struct SecretFromSliceError(usize);

impl Secret {
    pub fn from_random() -> Self {
        let mut rng = StdRng::from_entropy();
        let mut buffer = [0u8; SEED_LENGTH];
        rng.fill(&mut buffer);

        Self::from_byte_array(buffer)
    }

    pub fn from_byte_array(bytes: [u8; SEED_LENGTH]) -> Self {
        Self {
            curve: Curve::Secp256k1,
            inner: bytes,
        }
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, SecretFromSliceError> {
        if bytes.len() == SEED_LENGTH {
            Ok(Self {
                curve: Curve::Secp256k1,
                // Already checked length
                inner: bytes.try_into().unwrap(),
            })
        } else {
            Err(SecretFromSliceError(bytes.len()))
        }
    }

    pub fn from_base58check(encoded: &str) -> Result<Self, SecretFromEncodedError> {
        let decoded = base58check::decode(encoded).map_err(SecretFromEncodedError::DecodeError)?;

        match decoded.len() {
            WITH_SECP256K1_VERSION_SEED_LENGTH => {
                let version = &decoded[..1];
                let payload = &decoded[1..];

                if version != SECP256K1_SEED_VERSION {
                    return Err(SecretFromEncodedError::InvalidVersion(
                        SECP256K1_SEED_VERSION.to_vec(),
                        version.to_vec(),
                    ));
                }

                Ok(Self {
                    curve: Curve::Secp256k1,
                    // Already checked length
                    inner: payload.try_into().unwrap(),
                })
            }
            WITH_ED25519_VERSION_SEED_LENGTH => {
                let version = &decoded[..3];
                let payload = &decoded[3..];

                if version != ED25519_SEED_VERSION {
                    return Err(SecretFromEncodedError::InvalidVersion(
                        ED25519_SEED_VERSION.to_vec(),
                        version.to_vec(),
                    ));
                }

                Ok(Self {
                    curve: Curve::Ed25519,
                    // Already checked length
                    inner: payload.try_into().unwrap(),
                })
            }
            _ => Err(SecretFromEncodedError::InvalidPayloadLength(decoded.len())),
        }
    }

    pub fn private_key(&self) -> PrivateKey {
        self.into()
    }

    pub fn to_base58check(&self) -> String {
        base58check::encode(self.curve.into(), &self.inner)
    }

    pub fn to_bytes(&self) -> [u8; 16] {
        self.inner
    }
}

impl From<Curve> for &[u8] {
    fn from(version: Curve) -> Self {
        match version {
            Curve::Ed25519 => &ED25519_SEED_VERSION,
            Curve::Secp256k1 => &SECP256K1_SEED_VERSION,
        }
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

    const ENCODED_ED25519: &str = "spvyv3vG6GBG9sA6o4on8YDpxp9ZZ";
    const ED25519_BYTES: [u8; 16] = hex!("10ee423d1d21682fa4cbb6297f6f6fec");
    const ENCODED_SECP256K1: &str = "sn259rEFXrQrWyx3Q7XneWcwV6dfL";
    const SECP256K1_BYTES: [u8; 16] = hex!("CF2DE378FBDD7E2EE87D486DFB5A7BFF");

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ed25519_secret_from_base58check() {
        let secret = Secret::from_base58check(ENCODED_ED25519).unwrap();

        assert_eq!(ED25519_BYTES, secret.to_bytes());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ed25519_secret_to_base58check() {
        let secret = Secret::from_base58check(ENCODED_ED25519).unwrap();

        assert_eq!(ENCODED_ED25519, secret.to_base58check());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_secep256k1_secret_from_base58check() {
        let secret = Secret::from_base58check(ENCODED_SECP256K1).unwrap();

        println!("{:?}", hex::encode_upper(secret.to_bytes()));

        assert_eq!(SECP256K1_BYTES, secret.to_bytes());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_secep256k1_secret_to_base58check() {
        let secret = Secret::from_base58check(ENCODED_SECP256K1).unwrap();

        assert_eq!(ENCODED_SECP256K1, secret.to_base58check());
    }
}
