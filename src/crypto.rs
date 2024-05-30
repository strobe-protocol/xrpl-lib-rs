use ed25519_dalek::SignatureError;
use k256::{
    ecdsa::{signature::SignerMut, Signature as k256Signature, SigningKey},
    elliptic_curve::{Error, ScalarPrimitive},
    Secp256k1, SecretKey,
};
use ripemd::Ripemd160;
use sha2::{Digest, Sha256, Sha512};

use crate::{
    address::Address,
    hash::Hash,
    secret::{Curve, Secret},
};

#[derive(Debug, Clone)]
pub enum PrivateKey {
    Secp256k1(Secp256k1PrivateKey),
    Ed25519(Ed25519PrivateKey),
}

#[derive(Debug, Clone)]
pub enum PublicKey {
    Secp256k1(Secp256k1PublicKey),
    Ed25519(Ed25519PublicKey),
}

#[derive(Debug, Clone)]
pub struct Secp256k1PrivateKey {
    inner: SecretKey,
}

#[derive(Debug, Clone, Copy)]
pub struct Secp256k1PublicKey {
    inner: k256::PublicKey,
}

#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey {
    inner: ed25519_dalek::SecretKey,
}

#[derive(Debug, Clone)]
pub struct Ed25519PublicKey {
    inner: ed25519_dalek::VerifyingKey,
}

#[derive(Debug, Clone)]
pub struct Signature {
    r: [u8; 32],
    s: [u8; 32],
}

impl PrivateKey {
    pub fn to_bytes_be(&self) -> [u8; 32] {
        match self {
            PrivateKey::Secp256k1(private_key) => private_key.to_bytes_be(),
            PrivateKey::Ed25519(private_key) => private_key.to_bytes_be(),
        }
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Secp256k1(private_key) => PublicKey::Secp256k1(private_key.public_key()),
            PrivateKey::Ed25519(private_key) => PublicKey::Ed25519(private_key.public_key()),
        }
    }

    pub fn sign_hash(&self, hash: &Hash) -> Result<Signature, SignatureError> {
        match self {
            PrivateKey::Secp256k1(private_key) => private_key.sign_hash(hash),
            PrivateKey::Ed25519(private_key) => private_key.sign_hash(hash),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        match self {
            PrivateKey::Secp256k1(private_key) => private_key.sign(message),
            PrivateKey::Ed25519(private_key) => private_key.sign(message),
        }
    }
}

impl PublicKey {
    pub fn address(&self) -> Address {
        match self {
            PublicKey::Secp256k1(public_key) => public_key.address(),
            PublicKey::Ed25519(public_key) => public_key.address(),
        }
    }

    pub fn to_bytes_be(&self) -> [u8; 33] {
        match self {
            PublicKey::Secp256k1(public_key) => public_key.to_compressed_bytes_be(),
            PublicKey::Ed25519(public_key) => public_key.to_bytes_be(),
        }
    }
}

impl Secp256k1PrivateKey {
    pub fn sign_hash(&self, hash: &Hash) -> Result<Signature, SignatureError> {
        let hash_bytes: [u8; 32] = (*hash).into();

        let key: SigningKey = self.inner.clone().into();

        // TODO: check whether unwraps are safe here
        let (sig, _) = key.sign_prehash_recoverable(&hash_bytes)?;
        let r = sig.r().to_bytes().into();
        let s = sig.s().to_bytes().into();

        Ok(Signature { r, s })
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut key: SigningKey = self.inner.clone().into();

        let signature: k256Signature = key.sign(message);

        let r = signature.r().to_bytes().into();
        let s = signature.s().to_bytes().into();

        Signature { r, s }
    }

    pub fn public_key(&self) -> Secp256k1PublicKey {
        Secp256k1PublicKey {
            inner: self.inner.public_key(),
        }
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        self.inner.to_bytes().as_slice().try_into().unwrap()
    }
}

impl Secp256k1PublicKey {
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

impl Ed25519PrivateKey {
    pub fn sign_hash(&self, hash: &Hash) -> Result<Signature, SignatureError> {
        let hash_bytes: [u8; 32] = (*hash).into();

        let mut keypair = ed25519_dalek::SigningKey::from_bytes(&self.inner);
        let signature = keypair.sign(&hash_bytes);

        let signature = signature.to_bytes();
        let r = signature[..32].try_into().unwrap();
        let s = signature[32..].try_into().unwrap();

        Ok(Signature { r, s })
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        let mut keypair = ed25519_dalek::SigningKey::from_bytes(&self.inner);
        let signature = keypair.sign(message);

        let signature = signature.to_bytes();
        let r = signature[..32].try_into().unwrap();
        let s = signature[32..].try_into().unwrap();

        Signature { r, s }
    }

    pub fn public_key(&self) -> Ed25519PublicKey {
        let keypair = ed25519_dalek::SigningKey::from_bytes(&self.inner);

        Ed25519PublicKey {
            inner: keypair.verifying_key(),
        }
    }

    pub fn to_bytes_be(&self) -> [u8; 32] {
        self.inner
    }
}

impl Ed25519PublicKey {
    pub const PREFIX: u8 = 0xED;

    pub fn address(&self) -> Address {
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes_be());
        let hash = hasher.finalize();

        let mut hasher = Ripemd160::new();
        hasher.update(hash);
        let hash = hasher.finalize();

        let mut result = [0u8; 20];
        result.copy_from_slice(&hash);

        Address::from_byte_array(result)
    }

    pub fn to_bytes_be(&self) -> [u8; 33] {
        let mut buffer = [0u8; 33];
        buffer[0] = Self::PREFIX;
        buffer[1..].copy_from_slice(&self.inner.to_bytes());

        buffer
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
        match value.curve {
            Curve::Secp256k1 => {
                let mut buffer = [0u8; 20];

                // TODO: handle out of range private key
                buffer[..16].copy_from_slice(&value.to_bytes());

                let mut hasher = Sha512::new();
                hasher.update(buffer);
                let hash = hasher.finalize();

                let root_private_key =
                    ScalarPrimitive::<Secp256k1>::from_slice(&hash.as_slice()[..32])
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

                PrivateKey::Secp256k1(Secp256k1PrivateKey {
                    inner: SecretKey::new(root_private_key + intermediate_private_key),
                })
            }
            Curve::Ed25519 => {
                let sha512_half = sha2::Sha512::digest(value.to_bytes());
                // First 256 bits
                let raw_private_key = &sha512_half.as_slice()[..32];

                PrivateKey::Ed25519(Ed25519PrivateKey {
                    // We already know the length
                    inner: raw_private_key.try_into().unwrap(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    const SECP256K1_SECRET: &str = "spvyv3vG6GBG9sA6o4on8YDpxp9ZZ";
    const SECP256K1_ADDRESS: &str = "rh17sCvf1XKie2v9gdrZh3oDihyGsgkDdX";

    const ED25519_SECRET: &str = "sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r";
    const ED25519_ADDRESS: &str = "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD";

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_from_secp256k1_secret() {
        let private_key = Secret::from_base58check(SECP256K1_SECRET)
            .unwrap()
            .private_key();

        assert_eq!(
            hex!("1dcc1886fdceae9f60080111a19022172702b08df5b9d0c3aebcb0a004e49f0a"),
            private_key.to_bytes_be(),
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_secp256k1_private_key_to_public_key() {
        let private_key = Secret::from_base58check(SECP256K1_SECRET)
            .unwrap()
            .private_key();
        let public_key = private_key.public_key();

        if let PublicKey::Secp256k1(public_key) = public_key {
            assert_eq!(
                hex!("032dc8fe06a6969aef77325f4ea7710f25532e6e044c8d0befab585c542aa79a4c"),
                public_key.to_compressed_bytes_be()
            );
        } else {
            panic!("Invalid public key type");
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_secp256k1_public_key_to_address() {
        let private_key = Secret::from_base58check(SECP256K1_SECRET)
            .unwrap()
            .private_key();
        let public_key = private_key.public_key();

        if let PublicKey::Secp256k1(public_key) = public_key {
            assert_eq!(SECP256K1_ADDRESS, public_key.address().to_base58check());
        } else {
            panic!("Invalid public key type");
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_from_ed25519_secret() {
        let private_key = Secret::from_base58check(ED25519_SECRET)
            .unwrap()
            .private_key();

        assert_eq!(
            hex!("B4C4E046826BD26190D09715FC31F4E6A728204EADD112905B08B14B7F15C4F3"),
            private_key.to_bytes_be(),
        );
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ed25519_private_key_to_public_key() {
        let private_key = Secret::from_base58check(ED25519_SECRET)
            .unwrap()
            .private_key();
        let public_key = private_key.public_key();

        if let PublicKey::Ed25519(public_key) = public_key {
            assert_eq!(
                hex!("ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63"),
                public_key.to_bytes_be()
            );
        } else {
            panic!("Invalid public key type");
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ed25519_public_key_to_address() {
        let private_key = Secret::from_base58check(ED25519_SECRET)
            .unwrap()
            .private_key();
        let public_key = private_key.public_key();

        if let PublicKey::Ed25519(public_key) = public_key {
            assert_eq!(ED25519_ADDRESS, public_key.address().to_base58check());
        } else {
            panic!("Invalid public key type");
        }
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ed25519_sign() {
        let private_key = Secret::from_base58check(ED25519_SECRET)
            .unwrap()
            .private_key();
        if let PrivateKey::Ed25519(private_key) = private_key {
            let signature = private_key.sign("hello".as_bytes());

            assert_eq!(vec![0x30], signature.to_bytes())
        } else {
            panic!("Invalid public key type");
        }
    }
}
