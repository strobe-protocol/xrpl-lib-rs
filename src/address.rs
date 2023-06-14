use crate::base58check;

const ADDRESS_VERSION: u8 = 0;
const ADDRESS_LENGTH: usize = 20;

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

impl Address {
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

    pub fn to_bytes(&self) -> [u8; 20] {
        self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    #[test]
    fn test_address_from_base58check() {
        let address = Address::from_base58check("rh17sCvf1XKie2v9gdrZh3oDihyGsgkDdX").unwrap();

        assert_eq!(
            hex!("2a73c099d4b6e693facac67be9dc780043d78b12"),
            address.to_bytes(),
        )
    }
}
