use byteorder::{BigEndian, WriteBytesExt};

use crate::{address::Address, amount::Amount, hash::Hash};

#[derive(Clone)]
pub enum RippleFieldKind {
    TransactionType(TransactionTypeField),
    HookApiVersion(HookApiVersionField),
    NetworkId(NetworkIdField),
    Sequence(SequenceField),
    LastLedgerSequence(LastLedgerSequenceField),
    HookOn(HookOnField),
    HookNamespace(HookNamespaceField),
    Amount(AmountField),
    Fee(FeeField),
    SigningPubKey(SigningPubKeyField),
    TxnSignature(TxnSignatureField),
    CreateCode(CreateCodeField),
    Account(AccountField),
    Destination(DestinationField),
    Hook(HookField),
    Hooks(HooksField),
}

#[derive(Clone)]
pub struct UInt16Type(pub u16);
#[derive(Clone)]
pub struct UInt32Type(pub u32);
#[derive(Clone)]
pub struct Hash256Type(pub Hash);
#[derive(Clone)]
pub struct AmountType(pub Amount);
#[derive(Clone)]
pub struct BlobType(pub Vec<u8>);
#[derive(Clone)]
pub struct AccountIDType(pub Address);
#[derive(Clone)]
pub struct STObjectType(pub Vec<RippleFieldKind>);
#[derive(Clone)]
pub struct STArrayType<T>(pub Vec<T>);

#[derive(Clone)]
pub struct TransactionTypeField(pub UInt16Type);
#[derive(Clone)]
pub struct HookApiVersionField(pub UInt16Type);
#[derive(Clone)]
pub struct NetworkIdField(pub UInt32Type);
#[derive(Clone)]
pub struct SequenceField(pub UInt32Type);
#[derive(Clone)]
pub struct LastLedgerSequenceField(pub UInt32Type);
#[derive(Clone)]
pub struct HookOnField(pub Hash256Type);
#[derive(Clone)]
pub struct HookNamespaceField(pub Hash256Type);
#[derive(Clone)]
pub struct AmountField(pub AmountType);
#[derive(Clone)]
pub struct FeeField(pub AmountType);
#[derive(Clone)]
pub struct SigningPubKeyField(pub BlobType);
#[derive(Clone)]
pub struct TxnSignatureField(pub BlobType);
#[derive(Clone)]
pub struct CreateCodeField(pub BlobType);
#[derive(Clone)]
pub struct AccountField(pub AccountIDType);
#[derive(Clone)]
pub struct DestinationField(pub AccountIDType);
#[derive(Clone)]
pub struct HookField(pub STObjectType);
#[derive(Clone)]
pub struct HooksField(pub STArrayType<HookField>);

#[derive(Debug)]
struct FieldId {
    type_code: u16,
    field_code: u8,
}

#[allow(unused)]
struct FieldIdDecodeResult {
    field_id: FieldId,
    bytes_consumed: usize,
}

#[derive(Debug, thiserror::Error)]
enum FieldIdDecodeError {
    #[error("unexpected empty byte slice")]
    EmptySlice,
    #[error("byte slice too short")]
    SliceTooShort,
}

trait RippleType {
    fn type_code() -> u16;

    fn to_bytes(&self) -> Vec<u8>;
}

trait RippleField {
    type Type: RippleType;

    fn field_code() -> u8;

    fn value_ref(&self) -> &Self::Type;

    fn field_id() -> FieldId {
        FieldId {
            type_code: <Self::Type as RippleType>::type_code(),
            field_code: Self::field_code(),
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Self::field_id().encode();
        buffer.append(&mut self.value_ref().to_bytes());
        buffer
    }
}

impl FieldId {
    pub fn encode(&self) -> Vec<u8> {
        if self.type_code < 16 && self.field_code < 16 {
            vec![(self.type_code as u8) << 4 | self.field_code]
        } else if self.type_code >= 16 && self.field_code < 16 {
            vec![self.field_code, self.type_code as u8]
        } else if self.type_code < 16 && self.field_code >= 16 {
            vec![(self.type_code << 4) as u8, self.field_code]
        } else {
            vec![0, self.type_code as u8, self.field_code]
        }
    }

    #[allow(unused)]
    pub fn decode(encoded: &[u8]) -> Result<FieldIdDecodeResult, FieldIdDecodeError> {
        if encoded.is_empty() {
            return Err(FieldIdDecodeError::EmptySlice);
        }

        let high_4_bits = (encoded[0] >> 4) & 0b00001111;
        let low_4_bits = encoded[0] & 0b00001111;

        if high_4_bits != 0 && low_4_bits != 0 {
            // Type code < 16; Field code < 16
            Ok(FieldIdDecodeResult {
                field_id: Self {
                    type_code: high_4_bits.into(),
                    field_code: low_4_bits,
                },
                bytes_consumed: 1,
            })
        } else if high_4_bits == 0 && low_4_bits != 0 {
            // Type code >= 16; Field code < 16
            if encoded.len() < 2 {
                return Err(FieldIdDecodeError::SliceTooShort);
            }

            Ok(FieldIdDecodeResult {
                field_id: Self {
                    type_code: encoded[1].into(),
                    field_code: low_4_bits,
                },
                bytes_consumed: 2,
            })
        } else if high_4_bits != 0 && low_4_bits == 0 {
            // Type code < 16; Field code >= 16
            if encoded.len() < 2 {
                return Err(FieldIdDecodeError::SliceTooShort);
            }

            Ok(FieldIdDecodeResult {
                field_id: Self {
                    type_code: high_4_bits.into(),
                    field_code: encoded[1],
                },
                bytes_consumed: 2,
            })
        } else {
            // Type code >= 16; Field code >= 16
            if encoded.len() < 3 {
                return Err(FieldIdDecodeError::SliceTooShort);
            }

            Ok(FieldIdDecodeResult {
                field_id: Self {
                    type_code: encoded[1].into(),
                    field_code: encoded[2],
                },
                bytes_consumed: 3,
            })
        }
    }
}

impl RippleFieldKind {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            RippleFieldKind::TransactionType(inner) => inner.to_bytes(),
            RippleFieldKind::HookApiVersion(inner) => inner.to_bytes(),
            RippleFieldKind::NetworkId(inner) => inner.to_bytes(),
            RippleFieldKind::Sequence(inner) => inner.to_bytes(),
            RippleFieldKind::LastLedgerSequence(inner) => inner.to_bytes(),
            RippleFieldKind::HookOn(inner) => inner.to_bytes(),
            RippleFieldKind::HookNamespace(inner) => inner.to_bytes(),
            RippleFieldKind::Amount(inner) => inner.to_bytes(),
            RippleFieldKind::Fee(inner) => inner.to_bytes(),
            RippleFieldKind::SigningPubKey(inner) => inner.to_bytes(),
            RippleFieldKind::TxnSignature(inner) => inner.to_bytes(),
            RippleFieldKind::CreateCode(inner) => inner.to_bytes(),
            RippleFieldKind::Account(inner) => inner.to_bytes(),
            RippleFieldKind::Destination(inner) => inner.to_bytes(),
            RippleFieldKind::Hook(inner) => inner.to_bytes(),
            RippleFieldKind::Hooks(inner) => inner.to_bytes(),
        }
    }
}

impl RippleType for UInt16Type {
    fn type_code() -> u16 {
        1
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.write_u16::<BigEndian>(self.0).unwrap();
        buffer
    }
}
impl RippleType for UInt32Type {
    fn type_code() -> u16 {
        2
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];
        buffer.write_u32::<BigEndian>(self.0).unwrap();
        buffer
    }
}
impl RippleType for Hash256Type {
    fn type_code() -> u16 {
        5
    }

    fn to_bytes(&self) -> Vec<u8> {
        let bytes: [u8; 32] = self.0.into();
        bytes.to_vec()
    }
}
impl RippleType for AmountType {
    fn type_code() -> u16 {
        6
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.0.to_bytes()
    }
}
impl RippleType for BlobType {
    fn type_code() -> u16 {
        7
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];

        let len = self.0.len();

        if len <= 192 {
            buffer.push(len as u8);
        } else if len <= 12480 {
            let len = len - 193;

            let quotient = len / 256;
            let remainder = len - 256 * quotient;

            buffer.push((193 + quotient) as u8);
            buffer.push(remainder as u8);
        } else {
            todo!("handle long blob");
        }

        buffer.extend_from_slice(&self.0);
        buffer
    }
}
impl RippleType for AccountIDType {
    fn type_code() -> u16 {
        8
    }

    fn to_bytes(&self) -> Vec<u8> {
        let bytes = self.0.to_bytes();

        let mut buffer = vec![bytes.len() as u8];
        buffer.extend_from_slice(&bytes);
        buffer
    }
}
impl RippleType for STObjectType {
    fn type_code() -> u16 {
        14
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];

        // TODO: sort fields

        for element in self.0.iter() {
            buffer.append(&mut element.to_bytes());
        }

        buffer.push(0xe1);

        buffer
    }
}
impl<T> RippleType for STArrayType<T>
where
    T: RippleField,
{
    fn type_code() -> u16 {
        15
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = vec![];

        for element in self.0.iter() {
            buffer.append(&mut element.to_bytes());
        }

        buffer.push(0xf1);

        buffer
    }
}

impl RippleField for TransactionTypeField {
    type Type = UInt16Type;

    fn field_code() -> u8 {
        2
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for HookApiVersionField {
    type Type = UInt16Type;

    fn field_code() -> u8 {
        20
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for NetworkIdField {
    type Type = UInt32Type;

    fn field_code() -> u8 {
        1
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for SequenceField {
    type Type = UInt32Type;

    fn field_code() -> u8 {
        4
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for LastLedgerSequenceField {
    type Type = UInt32Type;

    fn field_code() -> u8 {
        27
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for HookOnField {
    type Type = Hash256Type;

    fn field_code() -> u8 {
        20
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for HookNamespaceField {
    type Type = Hash256Type;

    fn field_code() -> u8 {
        32
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for AmountField {
    type Type = AmountType;

    fn field_code() -> u8 {
        1
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for FeeField {
    type Type = AmountType;

    fn field_code() -> u8 {
        8
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for SigningPubKeyField {
    type Type = BlobType;

    fn field_code() -> u8 {
        3
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for TxnSignatureField {
    type Type = BlobType;

    fn field_code() -> u8 {
        4
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for CreateCodeField {
    type Type = BlobType;

    fn field_code() -> u8 {
        11
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for AccountField {
    type Type = AccountIDType;

    fn field_code() -> u8 {
        1
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for DestinationField {
    type Type = AccountIDType;

    fn field_code() -> u8 {
        3
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for HookField {
    type Type = STObjectType;

    fn field_code() -> u8 {
        14
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}
impl RippleField for HooksField {
    type Type = STArrayType<HookField>;

    fn field_code() -> u8 {
        11
    }

    fn value_ref(&self) -> &Self::Type {
        &self.0
    }
}

impl From<TransactionTypeField> for RippleFieldKind {
    fn from(value: TransactionTypeField) -> Self {
        Self::TransactionType(value)
    }
}
impl From<HookApiVersionField> for RippleFieldKind {
    fn from(value: HookApiVersionField) -> Self {
        Self::HookApiVersion(value)
    }
}
impl From<NetworkIdField> for RippleFieldKind {
    fn from(value: NetworkIdField) -> Self {
        Self::NetworkId(value)
    }
}
impl From<SequenceField> for RippleFieldKind {
    fn from(value: SequenceField) -> Self {
        Self::Sequence(value)
    }
}
impl From<LastLedgerSequenceField> for RippleFieldKind {
    fn from(value: LastLedgerSequenceField) -> Self {
        Self::LastLedgerSequence(value)
    }
}
impl From<HookOnField> for RippleFieldKind {
    fn from(value: HookOnField) -> Self {
        Self::HookOn(value)
    }
}
impl From<HookNamespaceField> for RippleFieldKind {
    fn from(value: HookNamespaceField) -> Self {
        Self::HookNamespace(value)
    }
}
impl From<AmountField> for RippleFieldKind {
    fn from(value: AmountField) -> Self {
        Self::Amount(value)
    }
}
impl From<FeeField> for RippleFieldKind {
    fn from(value: FeeField) -> Self {
        Self::Fee(value)
    }
}
impl From<SigningPubKeyField> for RippleFieldKind {
    fn from(value: SigningPubKeyField) -> Self {
        Self::SigningPubKey(value)
    }
}
impl From<TxnSignatureField> for RippleFieldKind {
    fn from(value: TxnSignatureField) -> Self {
        Self::TxnSignature(value)
    }
}
impl From<CreateCodeField> for RippleFieldKind {
    fn from(value: CreateCodeField) -> Self {
        Self::CreateCode(value)
    }
}
impl From<AccountField> for RippleFieldKind {
    fn from(value: AccountField) -> Self {
        Self::Account(value)
    }
}
impl From<DestinationField> for RippleFieldKind {
    fn from(value: DestinationField) -> Self {
        Self::Destination(value)
    }
}
impl From<HookField> for RippleFieldKind {
    fn from(value: HookField) -> Self {
        Self::Hook(value)
    }
}
impl From<HooksField> for RippleFieldKind {
    fn from(value: HooksField) -> Self {
        Self::Hooks(value)
    }
}
