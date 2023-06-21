use serde::{Deserialize, Serialize};

const HASH_LENGTH: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Hash {
    inner: [u8; HASH_LENGTH],
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.inner
    }
}

impl From<[u8; HASH_LENGTH]> for Hash {
    fn from(value: [u8; HASH_LENGTH]) -> Self {
        Self { inner: value }
    }
}

impl From<Hash> for [u8; HASH_LENGTH] {
    fn from(value: Hash) -> Self {
        value.inner
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&hex::encode(self.inner).to_ascii_uppercase())
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let bytes = hex::decode(value)
            .map_err(|err| serde::de::Error::custom(format!("unable to decode hex: {}", err)))?;

        if bytes.len() != HASH_LENGTH {
            return Err(serde::de::Error::custom(format!(
                "invalid byte length; expected: {}; actual: {}",
                HASH_LENGTH,
                bytes.len()
            )));
        }

        // We already checked length so unwrapping is fine
        let bytes: [u8; HASH_LENGTH] = bytes.try_into().unwrap();

        Ok(Self { inner: bytes })
    }
}
