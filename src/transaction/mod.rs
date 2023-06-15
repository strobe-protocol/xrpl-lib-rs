use sha2::{Digest, Sha512};

use crate::{
    address::Address,
    crypto::{PrivateKey, PublicKey, Signature},
    hash::Hash,
    transaction::field::*,
};

mod field;

// TODO: support `flags`, `memos`, and `hook_parameters`
// TODO: support non-XRP payments (`amount`)
#[derive(Debug, Clone)]
pub struct UnsignedPaymentTransaction {
    //
    // Common tx fields
    //
    pub account: Address,
    pub network_id: u32,
    pub fee: u64,
    pub sequence: u32,
    pub signing_pub_key: PublicKey,
    //
    // Payment specific fields
    //
    pub amount: u64,
    pub destination: Address,
}

#[derive(Debug, Clone)]
pub struct UnsignedSetHookTransaction {
    //
    // Common tx fields
    //
    pub account: Address,
    pub network_id: u32,
    pub fee: u64,
    pub sequence: u32,
    pub signing_pub_key: PublicKey,
    //
    // SetHook specific fields
    //
    pub hooks: Vec<Hook>,
}

#[derive(Debug, Clone)]
pub struct SignedPaymentTransaction {
    pub payload: UnsignedPaymentTransaction,
    pub signature: Signature,
}

#[derive(Debug, Clone)]
pub struct SignedSetHookTransaction {
    pub payload: UnsignedSetHookTransaction,
    pub signature: Signature,
}

#[derive(Debug, Clone)]
pub struct Hook {
    pub hook_api_version: u16,
    // flags
    pub hook_on: Hash,
    pub hook_namespace: Hash,
    pub create_code: Vec<u8>,
}

impl UnsignedPaymentTransaction {
    pub fn sign(&self, key: &PrivateKey) -> SignedPaymentTransaction {
        SignedPaymentTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash()),
        }
    }

    pub fn sig_hash(&self) -> Hash {
        let fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0x00)).into(),
            NetworkIdField(UInt32Type(self.network_id)).into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            AmountField(AmountType(self.amount)).into(),
            FeeField(AmountType(self.fee)).into(),
            SigningPubKeyField(BlobType(
                self.signing_pub_key.to_compressed_bytes_be().to_vec(),
            ))
            .into(),
            AccountField(AccountIDType(self.account)).into(),
            DestinationField(AccountIDType(self.destination)).into(),
        ];

        // TODO: sort fields

        let mut buffer = vec![0x53, 0x54, 0x58, 0x00];

        for field in fields.iter() {
            let mut current = field.to_bytes();
            buffer.append(&mut current);
        }

        let mut hasher = Sha512::new();
        hasher.update(&buffer);
        let hash = hasher.finalize();

        let half_hash: [u8; 32] = hash[..32].try_into().unwrap();
        half_hash.into()
    }
}

impl UnsignedSetHookTransaction {
    pub fn sign(&self, key: &PrivateKey) -> SignedSetHookTransaction {
        SignedSetHookTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash()),
        }
    }

    pub fn sig_hash(&self) -> Hash {
        let fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0x16)).into(),
            NetworkIdField(UInt32Type(self.network_id)).into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            FeeField(AmountType(self.fee)).into(),
            SigningPubKeyField(BlobType(
                self.signing_pub_key.to_compressed_bytes_be().to_vec(),
            ))
            .into(),
            AccountField(AccountIDType(self.account)).into(),
            HooksField(STArrayType(
                self.hooks.iter().map(|item| item.into()).collect(),
            ))
            .into(),
        ];

        // TODO: sort fields

        let mut buffer = vec![0x53, 0x54, 0x58, 0x00];

        for field in fields.iter() {
            let mut current = field.to_bytes();
            buffer.append(&mut current);
        }

        let mut hasher = Sha512::new();
        hasher.update(&buffer);
        let hash = hasher.finalize();

        let half_hash: [u8; 32] = hash[..32].try_into().unwrap();
        half_hash.into()
    }
}

impl SignedPaymentTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        let fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0)).into(),
            NetworkIdField(UInt32Type(self.payload.network_id)).into(),
            SequenceField(UInt32Type(self.payload.sequence)).into(),
            AmountField(AmountType(self.payload.amount)).into(),
            FeeField(AmountType(self.payload.fee)).into(),
            SigningPubKeyField(BlobType(
                self.payload
                    .signing_pub_key
                    .to_compressed_bytes_be()
                    .to_vec(),
            ))
            .into(),
            TxnSignatureField(BlobType(self.signature.to_bytes().to_vec())).into(),
            AccountField(AccountIDType(self.payload.account)).into(),
            DestinationField(AccountIDType(self.payload.destination)).into(),
        ];

        // TODO: sort fields

        let mut buffer = vec![];

        for field in fields.iter() {
            let mut current = field.to_bytes();
            buffer.append(&mut current);
        }

        buffer
    }
}

impl SignedSetHookTransaction {
    pub fn to_bytes(&self) -> Vec<u8> {
        let fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0x16)).into(),
            NetworkIdField(UInt32Type(self.payload.network_id)).into(),
            SequenceField(UInt32Type(self.payload.sequence)).into(),
            FeeField(AmountType(self.payload.fee)).into(),
            SigningPubKeyField(BlobType(
                self.payload
                    .signing_pub_key
                    .to_compressed_bytes_be()
                    .to_vec(),
            ))
            .into(),
            TxnSignatureField(BlobType(self.signature.to_bytes().to_vec())).into(),
            AccountField(AccountIDType(self.payload.account)).into(),
            HooksField(STArrayType(
                self.payload.hooks.iter().map(|item| item.into()).collect(),
            ))
            .into(),
        ];

        // TODO: sort fields

        let mut buffer = vec![];

        for field in fields.iter() {
            let mut current = field.to_bytes();
            buffer.append(&mut current);
        }

        buffer
    }
}

impl From<&Hook> for HookField {
    fn from(value: &Hook) -> Self {
        HookField(STObjectType(vec![
            HookApiVersionField(UInt16Type(value.hook_api_version)).into(),
            HookOnField(Hash256Type(value.hook_on)).into(),
            HookNamespaceField(Hash256Type(value.hook_namespace)).into(),
            CreateCodeField(BlobType(value.create_code.clone())).into(),
        ]))
    }
}

#[cfg(test)]
mod tests {
    use crate::secret::Secret;

    use super::*;

    use hex_literal::hex;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_sign_payment_transaction() {
        const EXPECTED_ENCODED: &[u8] = &hex!(
            "120000210000535a2400000064614000000005f5e10068400000000000001473\
            21032dc8fe06a6969aef77325f4ea7710f25532e6e044c8d0befab585c542aa7\
            9a4c7446304402206e1265ffccb19a3c71b46b28df9e02b8ee414dbc0d9d7759\
            d83df168ffdcb31202205a8c9d609e8fa744167aa6fc61881920919ee9d10fa7\
            9f89ab200e8b9f92aa5781142a73c099d4b6e693facac67be9dc780043d78b12\
            83142bb872bde0610250cd42abf8c099194380769266"
        );

        let private_key = Secret::from_base58check("spvyv3vG6GBG9sA6o4on8YDpxp9ZZ")
            .unwrap()
            .private_key();

        let unsigned_payment = UnsignedPaymentTransaction {
            account: Address::from_base58check("rh17sCvf1XKie2v9gdrZh3oDihyGsgkDdX").unwrap(),
            network_id: 21338,
            fee: 20,
            sequence: 100,
            signing_pub_key: private_key.public_key(),
            amount: 100000000,
            destination: Address::from_base58check("rhzBrANLLrt2H9TxrLVkvTsQHuZ3sfFXEW").unwrap(),
        };

        let signed_payment = unsigned_payment.sign(&private_key);

        assert_eq!(EXPECTED_ENCODED, signed_payment.to_bytes());
    }
}
