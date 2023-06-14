use k256::{elliptic_curve::ScalarPrimitive, Secp256k1, SecretKey};
use sha2::{Digest, Sha512};

use crate::base58check;

const SEED_VERSION: u8 = 33;
const SEED_LENGTH: usize = 16;

pub struct PrivateKey {
    inner: SecretKey,
}

#[derive(Debug, thiserror::Error)]
pub enum PrivateKeyFromSecretError {
    #[error(transparent)]
    DecodeError(base58check::DecodeError),
    #[error("invalid base58check version; expected: 33; actual: {0}")]
    InvalidVersion(u8),
    #[error("invalid seed byte length; expected: 16; actual: {0}")]
    InvalidSeedLength(usize),
}

impl PrivateKey {
    pub fn from_secret(secret: &str) -> Result<Self, PrivateKeyFromSecretError> {
        let decoded =
            base58check::decode(secret).map_err(PrivateKeyFromSecretError::DecodeError)?;

        if decoded.version != SEED_VERSION {
            return Err(PrivateKeyFromSecretError::InvalidVersion(decoded.version));
        }

        if decoded.payload.len() != SEED_LENGTH {
            return Err(PrivateKeyFromSecretError::InvalidSeedLength(
                decoded.payload.len(),
            ));
        }

        let mut buffer = [0u8; 20];

        // TODO: handle out of range private key
        buffer[..16].copy_from_slice(&decoded.payload);

        let mut hasher = Sha512::new();
        hasher.update(buffer);
        let hash = hasher.finalize();

        let root_private_key = ScalarPrimitive::<Secp256k1>::from_slice(&hash.as_slice()[..32])
            .expect("out of range private key not handled");
        let root_public_key_bytes = SecretKey::new(root_private_key)
            .public_key()
            .to_sec1_bytes();

        let mut buffer = [0u8; 41];

        // TODO: handle out of range private key
        buffer[..33].copy_from_slice(&root_public_key_bytes);

        let mut hasher = Sha512::new();
        hasher.update(buffer);
        let hash = hasher.finalize();

        let intermediate_private_key =
            ScalarPrimitive::<Secp256k1>::from_slice(&hash.as_slice()[..32])
                .expect("out of range private key not handled");

        Ok(Self {
            inner: SecretKey::new(root_private_key + intermediate_private_key),
        })
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        self.inner.to_bytes().as_slice().try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn test_from_secret() {
        let key = PrivateKey::from_secret("spvyv3vG6GBG9sA6o4on8YDpxp9ZZ").unwrap();

        assert_eq!(
            hex!("1dcc1886fdceae9f60080111a19022172702b08df5b9d0c3aebcb0a004e49f0a"),
            key.to_bytes_be(),
        );
    }
}
