use num_bigint::BigUint;
use num_traits::{One, Zero};
use sha2::Digest;

const ALPHABET_SIZE: usize = 58;
const ALPHABET: &[u8; ALPHABET_SIZE] =
    b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
const ALPHABET_ZERO: char = 'c';

#[derive(Debug)]
pub struct DecodeResult {
    pub version: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid digit: {0}")]
    InvalidDigit(char),
    #[error("checksum mismatch; expected: {expected:?}; actual: {actual:?}")]
    ChecksumMismatch { expected: [u8; 4], actual: [u8; 4] },
}

pub fn encode(version: u8, payload: &[u8]) -> String {
    let mut buffer = vec![version];
    buffer.extend_from_slice(payload);

    let mut hasher = sha2::Sha256::new();
    hasher.update(&buffer);
    let hash = hasher.finalize();

    let mut hasher = sha2::Sha256::new();
    hasher.update(hash);
    let hash = hasher.finalize();

    // Checksum at the end
    buffer.extend_from_slice(&hash[..4]);

    let mut result = String::new();

    loop {
        if buffer.is_empty() || buffer[0] != 0 {
            break;
        }

        result.push(ALPHABET_ZERO);
        buffer.remove(0);
    }

    let mut num = BigUint::from_bytes_be(&buffer);
    let alphabet_size: BigUint = ALPHABET_SIZE.into();

    let mut non_zeros = vec![];

    loop {
        if num.is_zero() {
            break;
        }

        let quotient = &num / &alphabet_size;

        // Unwrapping here is safe as remainder is never larger than usize::MAX
        let remainder: usize = (&num - (&quotient * &alphabet_size)).try_into().unwrap();

        non_zeros.push(ALPHABET[remainder]);
        num = quotient;
    }

    for byte in non_zeros.into_iter().rev() {
        result.push(byte as char);
    }

    result
}

pub fn decode(encoded: &str) -> Result<DecodeResult, DecodeError> {
    let mut bytes = vec![];

    let mut scale = BigUint::one();
    let mut sum = BigUint::zero();

    let alphabet_size: BigUint = ALPHABET_SIZE.into();

    for c in encoded.chars() {
        if c == ALPHABET_ZERO {
            bytes.push(0);
        } else {
            break;
        }
    }

    for c in encoded.chars().rev() {
        let digit: BigUint = ALPHABET
            .iter()
            .position(|item| *item == c as u8)
            .ok_or(DecodeError::InvalidDigit(c))?
            .into();

        sum += digit * &scale;
        scale *= &alphabet_size;
    }

    bytes.append(&mut sum.to_bytes_be());

    let content = &bytes[..(bytes.len() - 4)];
    let checksum = &bytes[(bytes.len() - 4)..];

    let mut hasher = sha2::Sha256::new();
    hasher.update(content);
    let hash = hasher.finalize();

    let mut hasher = sha2::Sha256::new();
    hasher.update(hash);
    let hash = hasher.finalize();

    if &hash[..4] != checksum {
        return Err(DecodeError::ChecksumMismatch {
            expected: checksum.try_into().unwrap(),
            actual: hash[..4].try_into().unwrap(),
        });
    }

    Ok(DecodeResult {
        version: content[0],
        payload: content[1..].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const DECODED_VERSION: u8 = 0x21;
    const DECODED_PAYLOAD: [u8; 16] = hex!("10ee423d1d21682fa4cbb6297f6f6fec");
    const ENCODED: &str = "spvyv3vG6GBG9sA6o4on8YDpxp9ZZ";

    #[test]
    fn test_encode() {
        assert_eq!(ENCODED, encode(DECODED_VERSION, &DECODED_PAYLOAD));
    }

    #[test]
    fn test_decode() {
        let decoded = decode(ENCODED).unwrap();

        assert_eq!(DECODED_VERSION, decoded.version);
        assert_eq!(&DECODED_PAYLOAD, &decoded.payload.as_slice());
    }
}
