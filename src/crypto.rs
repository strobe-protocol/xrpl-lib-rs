use k256::{ecdsa::SigningKey, elliptic_curve::ScalarPrimitive, Secp256k1, SecretKey};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

use crate::{address::Address, hash::Hash, secret::Secret};

#[derive(Debug, Clone)]
pub struct PrivateKey {
    inner: SecretKey,
}

#[derive(Debug, Clone, Copy)]
pub struct PublicKey {
    inner: k256::PublicKey,
}

#[derive(Debug, Clone)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl PrivateKey {
    pub fn sign_hash(&self, hash: &Hash) -> Signature {
        let hash_bytes: [u8; 32] = (*hash).into();

        let key: SigningKey = self.inner.clone().into();

        // TODO: check whether unwraps are safe here
        let (sig, _) = key.sign_prehash_recoverable(&hash_bytes).unwrap();
        let r = sig.r().to_bytes().try_into().unwrap();
        let s = sig.s().to_bytes().try_into().unwrap();

        Signature { r, s }
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.public_key(),
        }
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        self.inner.to_bytes().as_slice().try_into().unwrap()
    }
}

impl PublicKey {
    pub fn address(&self) -> Address {
        let mut hasher = Sha256::new();
        hasher.update(self.to_compressed_bytes_be());
        let hash = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(hash);
        let hash = hasher.finalize();

        let mut result = [0u8; 20];
        result.copy_from_slice(&hash);

        Address::from_byte_array(result)
    }

    pub fn to_compressed_bytes_be(&self) -> [u8; 33] {
        self.inner.to_sec1_bytes().as_ref().try_into().unwrap()
    }
}

impl Signature {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![0x30];

        let r_bytes = Self::to_signed_bytes(&self.r);
        let s_bytes = Self::to_signed_bytes(&self.s);

        buffer.push((2 + r_bytes.len() + 2 + s_bytes.len()) as u8);

        buffer.push(0x02);
        buffer.push(r_bytes.len() as u8);

        buffer.extend_from_slice(&r_bytes);

        buffer.push(0x02);
        buffer.push(s_bytes.len() as u8);

        buffer.extend_from_slice(&s_bytes);

        buffer
    }

    fn to_signed_bytes(bytes: &[u8]) -> Vec<u8> {
        if bytes[0] < 0b10000000u8 {
            bytes.to_vec()
        } else {
            let mut buffer = Vec::with_capacity(bytes.len() + 1);
            buffer.push(0);
            buffer.extend_from_slice(bytes);
            buffer
        }
    }
}

impl From<&Secret> for PrivateKey {
    fn from(value: &Secret) -> Self {
        let mut buffer = [0u8; 20];

        // TODO: handle out of range private key
        buffer[..16].copy_from_slice(&value.to_bytes());

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

        Self {
            inner: SecretKey::new(root_private_key + intermediate_private_key),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const SECRET: &str = "spvyv3vG6GBG9sA6o4on8YDpxp9ZZ";
    const ADDRESS: &str = "rh17sCvf1XKie2v9gdrZh3oDihyGsgkDdX";

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_from_secret() {
        let private_key = Secret::from_base58check(SECRET).unwrap().private_key();

        assert_eq!(
            hex!("1dcc1886fdceae9f60080111a19022172702b08df5b9d0c3aebcb0a004e49f0a"),
            private_key.to_bytes_be(),
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_private_key_to_public_key() {
        let private_key = Secret::from_base58check(SECRET).unwrap().private_key();
        let public_key = private_key.public_key();

        assert_eq!(
            hex!("032dc8fe06a6969aef77325f4ea7710f25532e6e044c8d0befab585c542aa79a4c"),
            public_key.to_compressed_bytes_be(),
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_public_key_to_address() {
        let private_key = Secret::from_base58check(SECRET).unwrap().private_key();
        let public_key = private_key.public_key();
        let address = public_key.address();

        assert_eq!(ADDRESS, address.to_base58check());
    }
}
