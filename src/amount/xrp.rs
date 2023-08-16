use super::SIGN_BIT_MASK;

const XRP_INDICATION_BIT_MASK: u64 = 0x8000000000000000;

const MAX_DROPS: u64 = 100000000000000000;
const XRP_AMOUNT_BYTES_LENGTH: usize = 8;

#[derive(Debug, Clone, Copy)]
pub struct XrpAmount(u64);

#[derive(Debug, thiserror::Error)]
#[error("amount of drops is out of range; expected: within the range of 0 to 100000000000000000")]
pub struct XrpAmountFromDropsError;

#[derive(Debug, thiserror::Error)]
pub enum XrpAmountFromByteSliceError {
    #[error("invalid byte length; expected: 8; actual: {0}")]
    InvalidLength(usize),
    #[error("the most significant bit of XRP amounts must be zero")]
    InvalidXrpBit,
    #[error("the sign bit of XRP amounts must be one")]
    InvalidSignBit,
    #[error(
        "amount of drops is out of range; expected: within the range of 0 to 100000000000000000"
    )]
    DropsOutOfRange,
}

impl XrpAmount {
    pub fn from_drops(drops: u64) -> Result<Self, XrpAmountFromDropsError> {
        if drops > MAX_DROPS {
            return Err(XrpAmountFromDropsError);
        }
        Ok(Self(drops))
    }

    pub fn from_byte_slice(bytes: &[u8]) -> Result<Self, XrpAmountFromByteSliceError> {
        let buffer: [u8; XRP_AMOUNT_BYTES_LENGTH] = bytes
            .try_into()
            .map_err(|_| XrpAmountFromByteSliceError::InvalidLength(bytes.len()))?;

        let raw_amount = u64::from_be_bytes(buffer);
        if raw_amount & XRP_INDICATION_BIT_MASK != 0 {
            return Err(XrpAmountFromByteSliceError::InvalidXrpBit);
        }
        if raw_amount & SIGN_BIT_MASK == 0 {
            return Err(XrpAmountFromByteSliceError::InvalidSignBit);
        }

        Ok(Self::from_drops(SIGN_BIT_MASK ^ raw_amount)?)
    }

    pub fn drops(self) -> u64 {
        self.0
    }

    pub fn to_bytes(&self) -> [u8; XRP_AMOUNT_BYTES_LENGTH] {
        (self.0 | SIGN_BIT_MASK).to_be_bytes()
    }
}

impl From<XrpAmountFromDropsError> for XrpAmountFromByteSliceError {
    fn from(_: XrpAmountFromDropsError) -> Self {
        Self::DropsOutOfRange
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_in_range_xrp() {
        let xrp_amount = XrpAmount::from_drops(111).expect("failed to parse xrp from drops");

        assert_eq!(xrp_amount.0, 111);
    }

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_out_of_range_xrp() {
        assert!(matches!(
            XrpAmount::from_drops(MAX_DROPS + 1),
            Err(XrpAmountFromDropsError)
        ));
    }
}
