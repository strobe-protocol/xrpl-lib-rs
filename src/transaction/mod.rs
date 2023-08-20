use sha2::{Digest, Sha512};

use crate::{
    address::Address,
    amount::{Amount, XrpAmount},
    crypto::{PrivateKey, PublicKey, Signature},
    hash::Hash,
    transaction::field::*,
};

mod field;

pub mod flags;
use flags::{AccountSetAsfFlags, AccountSetTfFlags};

#[derive(Debug, Clone)]
pub struct UnsignedPaymentTransaction {
    //
    // Common tx fields
    pub account: Address,
    pub network_id: u32,
    pub fee: XrpAmount,
    pub sequence: u32,
    pub last_ledger_sequence: u32,
    pub signing_pub_key: PublicKey,
    pub hook_parameters: Option<Vec<HookParameter>>,
    //
    // Payment specific fields
    pub amount: Amount,
    pub destination: Address,
}

#[derive(Debug, Clone)]
pub struct UnsignedSetHookTransaction {
    //
    // Common tx fields
    pub account: Address,
    pub network_id: u32,
    pub fee: XrpAmount,
    pub sequence: u32,
    pub last_ledger_sequence: u32,
    pub signing_pub_key: PublicKey,
    pub hook_parameters: Option<Vec<HookParameter>>,
    //
    // SetHook specific fields
    pub hooks: Vec<Hook>,
}

#[derive(Debug, Clone)]
pub struct UnsignedAccountSetTransaction {
    //
    // Common tx fields
    pub account: Address,
    pub network_id: u32,
    pub fee: XrpAmount,
    pub sequence: u32,
    pub last_ledger_sequence: u32,
    pub signing_pub_key: PublicKey,
    pub flags: Vec<AccountSetTfFlags>,
    pub hook_parameters: Option<Vec<HookParameter>>,
    //
    // AccountSet specific fields
    pub set_flag: Option<AccountSetAsfFlags>,
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
pub struct SignedAccountSetTransaction {
    pub payload: UnsignedAccountSetTransaction,
    pub signature: Signature,
}

#[derive(Debug, Clone)]
pub struct Hook {
    pub hook_api_version: u16,
    // flags
    pub hook_on: Hash,
    pub hook_namespace: Hash,
    pub create_code: Vec<u8>,
    pub hook_parameters: Vec<HookParameter>,
}

#[derive(Debug, Clone)]
pub struct HookParameter {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

impl UnsignedPaymentTransaction {
    pub fn sign(&self, key: &PrivateKey) -> SignedPaymentTransaction {
        SignedPaymentTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash()),
        }
    }

    pub fn sig_hash(&self) -> Hash {
        let mut fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0x00)).into(),
            NetworkIdField(UInt32Type(self.network_id)).into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.last_ledger_sequence)).into(),
            AmountField(AmountType(self.amount.clone())).into(),
            FeeField(AmountType(Amount::Xrp(self.fee))).into(),
            SigningPubKeyField(BlobType(
                self.signing_pub_key.to_compressed_bytes_be().to_vec(),
            ))
            .into(),
            AccountField(AccountIDType(self.account)).into(),
            DestinationField(AccountIDType(self.destination)).into(),
        ];
        if let Some(hook_parameters) = &self.hook_parameters {
            fields.push(
                HookParametersField(STArrayType(
                    hook_parameters.iter().map(|item| item.into()).collect(),
                ))
                .into(),
            );
        }

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
        let mut fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0x16)).into(),
            NetworkIdField(UInt32Type(self.network_id)).into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.last_ledger_sequence)).into(),
            FeeField(AmountType(Amount::Xrp(self.fee))).into(),
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
        if let Some(hook_parameters) = &self.hook_parameters {
            fields.push(
                HookParametersField(STArrayType(
                    hook_parameters.iter().map(|item| item.into()).collect(),
                ))
                .into(),
            );
        }

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

impl UnsignedAccountSetTransaction {
    pub fn sign(&self, key: &PrivateKey) -> SignedAccountSetTransaction {
        SignedAccountSetTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash()),
        }
    }

    pub fn sig_hash(&self) -> Hash {
        let mut fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(3)).into(),
            NetworkIdField(UInt32Type(self.network_id)).into(),
            FlagsField(UInt32Type(
                self.flags
                    .iter()
                    .fold(0, |acc_flags, flag| acc_flags | Into::<u32>::into(*flag)),
            ))
            .into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.last_ledger_sequence)).into(),
        ];
        if let Some(set_flag) = self.set_flag {
            fields.push(SetFlagField(UInt32Type(Into::<u32>::into(set_flag))).into());
        }
        fields.extend(vec![
            FeeField(AmountType(Amount::Xrp(self.fee))).into(),
            SigningPubKeyField(BlobType(
                self.signing_pub_key.to_compressed_bytes_be().to_vec(),
            ))
            .into(),
        ]);
        fields.push(AccountField(AccountIDType(self.account)).into());
        if let Some(hook_parameters) = &self.hook_parameters {
            fields.push(
                HookParametersField(STArrayType(
                    hook_parameters.iter().map(|item| item.into()).collect(),
                ))
                .into(),
            );
        }

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
    pub fn hash(&self) -> Hash {
        let mut buffer = vec![0x54, 0x58, 0x4e, 0x00];
        buffer.extend_from_slice(&self.to_bytes());

        let mut hasher = sha2::Sha512::new();
        hasher.update(&buffer);
        let hash = hasher.finalize();

        let half_hash: [u8; 32] = hash[..32].try_into().unwrap();
        half_hash.into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0)).into(),
            NetworkIdField(UInt32Type(self.payload.network_id)).into(),
            SequenceField(UInt32Type(self.payload.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.payload.last_ledger_sequence)).into(),
            AmountField(AmountType(self.payload.amount.clone())).into(),
            FeeField(AmountType(Amount::Xrp(self.payload.fee))).into(),
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
        if let Some(hook_parameters) = &self.payload.hook_parameters {
            fields.push(
                HookParametersField(STArrayType(
                    hook_parameters.iter().map(|item| item.into()).collect(),
                ))
                .into(),
            );
        }

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
    pub fn hash(&self) -> Hash {
        let mut buffer = vec![0x54, 0x58, 0x4e, 0x00];
        buffer.extend_from_slice(&self.to_bytes());

        let mut hasher = sha2::Sha512::new();
        hasher.update(&buffer);
        let hash = hasher.finalize();

        let half_hash: [u8; 32] = hash[..32].try_into().unwrap();
        half_hash.into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0x16)).into(),
            NetworkIdField(UInt32Type(self.payload.network_id)).into(),
            SequenceField(UInt32Type(self.payload.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.payload.last_ledger_sequence)).into(),
            FeeField(AmountType(Amount::Xrp(self.payload.fee))).into(),
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
        if let Some(hook_parameters) = &self.payload.hook_parameters {
            fields.push(
                HookParametersField(STArrayType(
                    hook_parameters.iter().map(|item| item.into()).collect(),
                ))
                .into(),
            );
        }

        // TODO: sort fields

        let mut buffer = vec![];

        for field in fields.iter() {
            let mut current = field.to_bytes();
            buffer.append(&mut current);
        }

        buffer
    }
}

impl SignedAccountSetTransaction {
    pub fn hash(&self) -> Hash {
        let mut buffer = vec![0x54, 0x58, 0x4e, 0x00];
        buffer.extend_from_slice(&self.to_bytes());

        let mut hasher = sha2::Sha512::new();
        hasher.update(&buffer);
        let hash = hasher.finalize();

        let half_hash: [u8; 32] = hash[..32].try_into().unwrap();
        half_hash.into()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(3)).into(),
            NetworkIdField(UInt32Type(self.payload.network_id)).into(),
            FlagsField(UInt32Type(
                self.payload
                    .flags
                    .iter()
                    .fold(0, |acc_flags, flag| acc_flags | Into::<u32>::into(*flag)),
            ))
            .into(),
            SequenceField(UInt32Type(self.payload.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.payload.last_ledger_sequence)).into(),
        ];
        if let Some(set_flag) = self.payload.set_flag {
            fields.push(SetFlagField(UInt32Type(Into::<u32>::into(set_flag))).into());
        }
        fields.extend(vec![
            FeeField(AmountType(Amount::Xrp(self.payload.fee))).into(),
            SigningPubKeyField(BlobType(
                self.payload
                    .signing_pub_key
                    .to_compressed_bytes_be()
                    .to_vec(),
            ))
            .into(),
            TxnSignatureField(BlobType(self.signature.to_bytes().to_vec())).into(),
        ]);
        fields.push(AccountField(AccountIDType(self.payload.account)).into());
        if let Some(hook_parameters) = &self.payload.hook_parameters {
            fields.push(
                HookParametersField(STArrayType(
                    hook_parameters.iter().map(|item| item.into()).collect(),
                ))
                .into(),
            );
        }

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
            HookParametersField(STArrayType(
                value
                    .hook_parameters
                    .iter()
                    .map(|item| item.into())
                    .collect(),
            ))
            .into(),
        ]))
    }
}

impl From<&HookParameter> for HookParameterField {
    fn from(value: &HookParameter) -> Self {
        HookParameterField(STObjectType(vec![
            HookParameterNameField(BlobType(value.name.clone())).into(),
            HookParameterValueField(BlobType(value.value.clone())).into(),
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
            "120000210000535a2400000064201b00000065614000000005f5e10\
            06840000000000000147321032dc8fe06a6969aef77325f4ea7710f2\
            5532e6e044c8d0befab585c542aa79a4c744630440220083a1287449\
            8456cb99f1603168cdd5a3d9ffb0ad602af1bce32a4cfd1322dee022\
            03dae0d9795c482082cb79db1a3a1a101edd2609808c0f8d0d49b279\
            21d4f2fae81142a73c099d4b6e693facac67be9dc780043d78b12831\
            42bb872bde0610250cd42abf8c099194380769266"
        );

        let private_key = Secret::from_base58check("spvyv3vG6GBG9sA6o4on8YDpxp9ZZ")
            .unwrap()
            .private_key();

        let unsigned_payment = UnsignedPaymentTransaction {
            account: Address::from_base58check("rh17sCvf1XKie2v9gdrZh3oDihyGsgkDdX").unwrap(),
            network_id: 21338,
            fee: XrpAmount::from_drops(20).unwrap(),
            sequence: 100,
            last_ledger_sequence: 101,
            signing_pub_key: private_key.public_key(),
            hook_parameters: None,
            amount: Amount::Xrp(XrpAmount::from_drops(100000000).unwrap()),
            destination: Address::from_base58check("rhzBrANLLrt2H9TxrLVkvTsQHuZ3sfFXEW").unwrap(),
        };

        let signed_payment = unsigned_payment.sign(&private_key);

        assert_eq!(EXPECTED_ENCODED, signed_payment.to_bytes());
    }
}
