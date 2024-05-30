use ed25519_dalek::SignatureError;
use sha2::{Digest, Sha512};

use crate::{
    address::Address,
    amount::{Amount, TokenAmount, XrpAmount},
    crypto::{PrivateKey, PublicKey, Signature},
    hash::Hash,
    transaction::field::*,
};

mod field;

pub mod flags;
use flags::{AccountSetAsfFlags, AccountSetTfFlags, TrustSetFlags};

#[derive(Debug, Clone)]
pub struct UnsignedPaymentTransaction {
    //
    // Common tx fields
    pub account: Address,
    pub fee: XrpAmount,
    pub sequence: u32,
    pub last_ledger_sequence: u32,
    pub signing_pub_key: PublicKey,
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
pub struct UnsignedTrustSetTransaction {
    //
    // Common tx fields
    pub account: Address,
    pub network_id: u32,
    pub fee: XrpAmount,
    pub sequence: u32,
    pub last_ledger_sequence: u32,
    pub signing_pub_key: PublicKey,
    pub flags: Vec<TrustSetFlags>,
    //
    // TrustSet specific fields
    pub limit_amount: TokenAmount,
}

#[derive(Debug, Clone)]
pub struct UnsignedInvokeTransaction {
    //
    // Common tx fields
    pub account: Address,
    pub network_id: u32,
    pub fee: XrpAmount,
    pub sequence: u32,
    pub last_ledger_sequence: u32,
    pub signing_pub_key: PublicKey,
    pub flags: u32,
    pub hook_parameters: Option<Vec<HookParameter>>,
    //
    // Invoke specific fields
    pub destination: Address,
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
pub struct SignedTrustSetTransaction {
    pub payload: UnsignedTrustSetTransaction,
    pub signature: Signature,
}

#[derive(Debug, Clone)]
pub struct SignedInvokeTransaction {
    pub payload: UnsignedInvokeTransaction,
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
    pub fn sign(&self, key: &PrivateKey) -> Result<SignedPaymentTransaction, SignatureError> {
        Ok(SignedPaymentTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash())?,
        })
    }

    pub fn sig_hash(&self) -> Hash {
        let fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0x00)).into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.last_ledger_sequence)).into(),
            AmountField(AmountType(self.amount.clone())).into(),
            FeeField(AmountType(Amount::Xrp(self.fee))).into(),
            SigningPubKeyField(BlobType(self.signing_pub_key.to_bytes_be().to_vec())).into(),
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
    pub fn sign(&self, key: &PrivateKey) -> Result<SignedSetHookTransaction, SignatureError> {
        Ok(SignedSetHookTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash())?,
        })
    }

    pub fn sig_hash(&self) -> Hash {
        let mut fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0x16)).into(),
            NetworkIdField(UInt32Type(self.network_id)).into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.last_ledger_sequence)).into(),
            FeeField(AmountType(Amount::Xrp(self.fee))).into(),
            SigningPubKeyField(BlobType(self.signing_pub_key.to_bytes_be().to_vec())).into(),
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
    pub fn sign(&self, key: &PrivateKey) -> Result<SignedAccountSetTransaction, SignatureError> {
        Ok(SignedAccountSetTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash())?,
        })
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
            SigningPubKeyField(BlobType(self.signing_pub_key.to_bytes_be().to_vec())).into(),
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

impl UnsignedTrustSetTransaction {
    pub fn sign(&self, key: &PrivateKey) -> Result<SignedTrustSetTransaction, SignatureError> {
        Ok(SignedTrustSetTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash())?,
        })
    }

    pub fn sig_hash(&self) -> Hash {
        let fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(20)).into(),
            NetworkIdField(UInt32Type(self.network_id)).into(),
            FlagsField(UInt32Type(
                self.flags
                    .iter()
                    .fold(0, |acc_flags, flag| acc_flags | Into::<u32>::into(*flag)),
            ))
            .into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.last_ledger_sequence)).into(),
            LimitAmountField(AmountType(Amount::Token(self.limit_amount.clone()))).into(),
            FeeField(AmountType(Amount::Xrp(self.fee))).into(),
            SigningPubKeyField(BlobType(self.signing_pub_key.to_bytes_be().to_vec())).into(),
            AccountField(AccountIDType(self.account)).into(),
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

impl UnsignedInvokeTransaction {
    pub fn sign(&self, key: &PrivateKey) -> Result<SignedInvokeTransaction, SignatureError> {
        Ok(SignedInvokeTransaction {
            payload: self.clone(),
            signature: key.sign_hash(&self.sig_hash())?,
        })
    }

    pub fn sig_hash(&self) -> Hash {
        let mut fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(99)).into(),
            NetworkIdField(UInt32Type(self.network_id)).into(),
            FlagsField(UInt32Type(self.flags)).into(),
            SequenceField(UInt32Type(self.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.last_ledger_sequence)).into(),
            FeeField(AmountType(Amount::Xrp(self.fee))).into(),
            SigningPubKeyField(BlobType(self.signing_pub_key.to_bytes_be().to_vec())).into(),
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
        let fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(0)).into(),
            SequenceField(UInt32Type(self.payload.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.payload.last_ledger_sequence)).into(),
            AmountField(AmountType(self.payload.amount.clone())).into(),
            FeeField(AmountType(Amount::Xrp(self.payload.fee))).into(),
            SigningPubKeyField(BlobType(
                self.payload.signing_pub_key.to_bytes_be().to_vec(),
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
                self.payload.signing_pub_key.to_bytes_be().to_vec(),
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
                self.payload.signing_pub_key.to_bytes_be().to_vec(),
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

impl SignedTrustSetTransaction {
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
        let fields: Vec<RippleFieldKind> = vec![
            TransactionTypeField(UInt16Type(20)).into(),
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
            LimitAmountField(AmountType(Amount::Token(self.payload.limit_amount.clone()))).into(),
            FeeField(AmountType(Amount::Xrp(self.payload.fee))).into(),
            SigningPubKeyField(BlobType(
                self.payload.signing_pub_key.to_bytes_be().to_vec(),
            ))
            .into(),
            TxnSignatureField(BlobType(self.signature.to_bytes().to_vec())).into(),
            AccountField(AccountIDType(self.payload.account)).into(),
        ];

        let mut buffer = vec![];

        for field in fields.iter() {
            let mut current = field.to_bytes();
            buffer.append(&mut current);
        }

        buffer
    }
}

impl SignedInvokeTransaction {
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
            TransactionTypeField(UInt16Type(99)).into(),
            NetworkIdField(UInt32Type(self.payload.network_id)).into(),
            FlagsField(UInt32Type(self.payload.flags)).into(),
            SequenceField(UInt32Type(self.payload.sequence)).into(),
            LastLedgerSequenceField(UInt32Type(self.payload.last_ledger_sequence)).into(),
            FeeField(AmountType(Amount::Xrp(self.payload.fee))).into(),
            SigningPubKeyField(BlobType(
                self.payload.signing_pub_key.to_bytes_be().to_vec(),
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
    fn test_secp256k1_sign_payment_transaction() {
        const EXPECTED_ENCODED: &[u8] = &hex!(
            "1200002400000064201B00000065614000000005F5E1006840000000000000147321032DC8FE06A6969AEF77325F4EA7710F25532E6E044C8D0BEFAB585C542AA79A4C74463044022079FF9D3D77FCCC98F2DCA73FDAE29226743E8ED8CB2EC1C4E76F222A661B4E64022072706F585BF091A0929659EE784470591ABAEE0BB95D2A804236583231B802BB81142A73C099D4B6E693FACAC67BE9DC780043D78B1283142BB872BDE0610250CD42ABF8C099194380769266"
        );

        let private_key = Secret::from_base58check("spvyv3vG6GBG9sA6o4on8YDpxp9ZZ")
            .unwrap()
            .private_key();

        let unsigned_payment = UnsignedPaymentTransaction {
            account: Address::from_base58check("rh17sCvf1XKie2v9gdrZh3oDihyGsgkDdX").unwrap(),
            fee: XrpAmount::from_drops(20).unwrap(),
            sequence: 100,
            last_ledger_sequence: 101,
            signing_pub_key: private_key.public_key(),
            amount: Amount::Xrp(XrpAmount::from_drops(100000000).unwrap()),
            destination: Address::from_base58check("rhzBrANLLrt2H9TxrLVkvTsQHuZ3sfFXEW").unwrap(),
        };

        let signed_payment = unsigned_payment
            .sign(&private_key)
            .expect("Failed to sign transaction");

        assert_eq!(EXPECTED_ENCODED, signed_payment.to_bytes());
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_ed25519_sign_payment_transaction() {
        const EXPECTED_ENCODED: &[u8] = &hex!(
            "1200002400000064201B00000065614000000005F5E1006840000000000000147321EDB0AB92740256BFCE24DF08678CF28C9F9AC16C9DC39A1A7D0423B05530B6FAE7744041F80E1DCDCC051918E6C03BADFFFFD15FD08660DBCAB36B98300B7FD8F0E9D3E165307B84C89414B73471F1ECCE66DA26AE25B423D1CA3A61F2D04284D02E0581142789BD47FAC4E8CA459F4EBEE392F6AD6AD7A84383142BB872BDE0610250CD42ABF8C099194380769266"
        );

        let private_key = Secret::from_base58check("sEdTFjQkShqBAfj8tBLdUaJsdHFfgfX")
            .unwrap()
            .private_key();

        println!(
            "{:?}",
            hex::encode_upper(private_key.public_key().address().to_bytes())
        );

        let unsigned_payment = UnsignedPaymentTransaction {
            account: private_key.public_key().address(),
            fee: XrpAmount::from_drops(20).unwrap(),
            sequence: 100,
            last_ledger_sequence: 101,
            signing_pub_key: private_key.public_key(),
            amount: Amount::Xrp(XrpAmount::from_drops(100000000).unwrap()),
            destination: Address::from_base58check("rhzBrANLLrt2H9TxrLVkvTsQHuZ3sfFXEW").unwrap(),
        };

        let signed_payment = unsigned_payment
            .sign(&private_key)
            .expect("Failed to sign transaction");

        println!("{:?}", hex::encode_upper(signed_payment.to_bytes()));

        assert_eq!(EXPECTED_ENCODED, signed_payment.to_bytes());
    }
}

// [18, 0, 0, 36, 0, 0, 0, 100, 32, 27, 0, 0, 0, 101, 97, 64, 0, 0, 0, 5, 245, 225, 0, 104, 64, 0,
// 0, 0, 0, 0, 0, 20, 115, 33, 237, 209, 195, 195, 73, 99, 179, 32, 229, 24, 81, 87, 136, 92, 191,
// 106, 15, 238, 195, 157, 235, 48, 112, 98, 130, 231, 228, 239, 109, 22, 58, 163, 133, 116, 64, 51,
// 246, 17, 7, 103, 130, 171, 216, 231, 78, 248, 168, 227, 85, 48, 4, 166, 47, 53, 92, 29, 196, 94,
// 91, 128, 188, 237, 67, 80, 15, 87, 213, 4, 72, 242, 251, 116, 2, 116, 129, 66, 231, 40, 130, 31,
// 219, 243, 183, 57, 248, 17, 64, 82, 136, 158, 175, 19, 193, 169, 10, 6, 112, 179, 11, 129, 20,
// 208, 168, 99, 125, 24, 99, 194, 137, 122, 181, 12, 51, 186, 123, 184, 139, 231, 107, 54, 99, 131,
// 20, 43, 184, 114, 189, 224, 97, 2, 80, 205, 66, 171, 248, 192, 153, 25, 67, 128, 118, 146, 102]
// [18, 0, 0, 36, 0, 0, 0, 100, 32, 27, 0, 0, 0, 101, 97, 64, 0, 0, 0, 5, 245, 225, 0, 104, 64, 0,
// 0, 0, 0, 0, 0, 20, 115, 33, 3, 45, 200, 254, 6, 166, 150, 154, 239, 119, 50, 95, 78, 167, 113,
// 15, 37, 83, 46, 110, 4, 76, 141, 11, 239, 171, 88, 92, 84, 42, 167, 154, 76, 116, 70, 48, 68, 2,
// 32, 121, 255, 157, 61, 119, 252, 204, 152, 242, 220, 167, 63, 218, 226, 146, 38, 116, 62, 142,
// 216, 203, 46, 193, 196, 231, 111, 34, 42, 102, 27, 78, 100, 2, 32, 114, 112, 111, 88, 91, 240,
// 145, 160, 146, 150, 89, 238, 120, 68, 112, 89, 26, 186, 238, 11, 185, 93, 42, 128, 66, 54, 88,
// 50, 49, 184, 2, 187, 129, 20, 42, 115, 192, 153, 212, 182, 230, 147, 250, 202, 198, 123, 233,
// 220, 120, 0, 67, 215, 139, 18, 131, 20, 43, 184, 114, 189, 224, 97, 2, 80, 205, 66, 171, 248,
// 192, 153, 25, 67, 128, 118, 146, 102]
