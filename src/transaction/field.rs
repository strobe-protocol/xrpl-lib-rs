use byteorder::{BigEndian, WriteBytesExt};

use crate::address::Address;

#[derive(Clone)]
pub enum RippleFieldKind {
    TransactionType(TransactionTypeField),
    NetworkId(NetworkIdField),
    Sequence(SequenceField),
    Amount(AmountField),
    Fee(FeeField),
    SigningPubKey(SigningPubKeyField),
    TxnSignature(TxnSignatureField),
    Account(AccountField),
    Destination(DestinationField),
}

#[derive(Clone)]
pub struct UInt16Type(pub u16);
#[derive(Clone)]
pub struct UInt32Type(pub u32);
#[derive(Clone)]
pub struct AmountType(pub u64);
#[derive(Clone)]
pub struct BlobType(pub Vec<u8>);
#[derive(Clone)]
pub struct AccountIDType(pub Address);

#[derive(Clone)]
pub struct TransactionTypeField(pub UInt16Type);
#[derive(Clone)]
pub struct NetworkIdField(pub UInt32Type);
#[derive(Clone)]
pub struct SequenceField(pub UInt32Type);
#[derive(Clone)]
pub struct AmountField(pub AmountType);
#[derive(Clone)]
pub struct FeeField(pub AmountType);
#[derive(Clone)]
pub struct SigningPubKeyField(pub BlobType);
#[derive(Clone)]
pub struct TxnSignatureField(pub BlobType);
#[derive(Clone)]
pub struct AccountField(pub AccountIDType);
#[derive(Clone)]
pub struct DestinationField(pub AccountIDType);

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
            RippleFieldKind::NetworkId(inner) => inner.to_bytes(),
            RippleFieldKind::Sequence(inner) => inner.to_bytes(),
            RippleFieldKind::Amount(inner) => inner.to_bytes(),
            RippleFieldKind::Fee(inner) => inner.to_bytes(),
            RippleFieldKind::SigningPubKey(inner) => inner.to_bytes(),
            RippleFieldKind::TxnSignature(inner) => inner.to_bytes(),
            RippleFieldKind::Account(inner) => inner.to_bytes(),
            RippleFieldKind::Destination(inner) => inner.to_bytes(),
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
impl RippleType for AmountType {
    fn type_code() -> u16 {
        6
    }

    fn to_bytes(&self) -> Vec<u8> {
        let xrp_amount = self.0 | 0x4000000000000000;

        let mut buffer = vec![];
        buffer.write_u64::<BigEndian>(xrp_amount).unwrap();
        buffer
    }
}
impl RippleType for BlobType {
    fn type_code() -> u16 {
        7
    }

    fn to_bytes(&self) -> Vec<u8> {
        if self.0.len() > 192 {
            todo!("handle long blob");
        }

        let mut buffer = vec![self.0.len() as u8];
        buffer.append(&mut self.0.clone());
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

impl RippleField for TransactionTypeField {
    type Type = UInt16Type;

    fn field_code() -> u8 {
        2
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

impl From<TransactionTypeField> for RippleFieldKind {
    fn from(value: TransactionTypeField) -> Self {
        Self::TransactionType(value)
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
