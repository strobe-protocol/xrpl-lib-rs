mod xrp;
pub use xrp::*;

mod token;
pub use token::*;

pub(crate) const SIGN_BIT_MASK: u64 = 0x4000000000000000;

#[derive(Debug, Clone)]
pub enum Amount {
    Xrp(XrpAmount),
    Token(TokenAmount),
}

impl Amount {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Xrp(amount) => amount.to_bytes().to_vec(),
            Self::Token(amount) => amount.to_bytes().to_vec(),
        }
    }
}

impl From<TokenAmount> for Amount {
    fn from(value: TokenAmount) -> Self {
        Self::Token(value)
    }
}

impl From<XrpAmount> for Amount {
    fn from(value: XrpAmount) -> Self {
        Self::Xrp(value)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde::Deserialize;

    use crate::{address::Address, currency_code::StandardCurrencyCode};

    use super::*;

    #[test]
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test::wasm_bindgen_test)]
    fn test_amount_to_bytes() {
        #[derive(Debug, Deserialize)]
        struct XrpSuccess {
            test_json: String,
            expected_hex: String,
            #[allow(unused)]
            is_native: bool,
        }

        #[derive(Debug, Deserialize)]
        struct XrpFailure {
            test_json: String,
            #[allow(unused)]
            error: String,
            #[allow(unused)]
            is_native: bool,
        }

        #[derive(Debug, Deserialize)]
        struct TokenTestJson {
            currency: String,
            value: String,
            issuer: String,
        }

        #[derive(Debug, Deserialize)]
        struct TokenSuccess {
            test_json: TokenTestJson,
            expected_hex: String,
        }

        #[derive(Debug, Deserialize)]
        struct TokenFailure {
            test_json: TokenTestJson,
            #[allow(unused)]
            error: String,
        }

        #[derive(Debug, Deserialize)]
        #[serde(untagged)]
        enum DataDrivenTest {
            XrpSuccess(XrpSuccess),
            XrpFailure(XrpFailure),
            TokenFailure(TokenFailure),
            TokenSuccess(TokenSuccess),
        }

        let json_str = include_str!("../../tests/data/amount.json");
        let data: Vec<DataDrivenTest> = serde_json::from_str(json_str).unwrap();

        for test_case in data.into_iter() {
            match test_case {
                DataDrivenTest::XrpSuccess(xrp_test_case) => {
                    let amount_from_bytes = XrpAmount::from_byte_slice(
                        &hex::decode(&xrp_test_case.expected_hex).unwrap(),
                    )
                    .expect("Failed to create amount from bytes");

                    assert_eq!(
                        amount_from_bytes.to_bytes()[..],
                        hex::decode(&xrp_test_case.expected_hex).unwrap()
                    );

                    let amount_from_json = xrp_test_case.test_json;
                    assert_eq!(
                        XrpAmount::from_drops(amount_from_json.parse::<u64>().unwrap())
                            .expect("failed to parse drops")
                            .to_bytes()[..],
                        hex::decode(xrp_test_case.expected_hex).unwrap()
                    );
                }
                DataDrivenTest::XrpFailure(xrp_test_case) => {
                    let amount_from_json = xrp_test_case.test_json;
                    assert!(
                        XrpAmount::from_drops(amount_from_json.parse::<u64>().unwrap()).is_err()
                    );
                }
                DataDrivenTest::TokenSuccess(success_case) => {
                    let amount_from_json = success_case.test_json;

                    let amount_from_bytes = TokenAmount::from_byte_slice(
                        &hex::decode(&success_case.expected_hex).unwrap(),
                    )
                    .expect("Failed to create amount from bytes");

                    assert_eq!(
                        amount_from_bytes.to_bytes()[..],
                        hex::decode(&success_case.expected_hex).unwrap()
                    );

                    let amount = Amount::Token(TokenAmount {
                        value: TokenValue::from_str(&amount_from_json.value)
                            .expect("failed to parse token amount: value"),
                        currency: StandardCurrencyCode::from_str(&amount_from_json.currency)
                            .expect("failed to parse token amount: currency")
                            .into(),
                        issuer: Address::from_base58check(&amount_from_json.issuer)
                            .expect("failed to parse token amount: value"),
                    });

                    let expected_bytes = hex::decode(success_case.expected_hex).unwrap();
                    assert_eq!(amount.to_bytes(), expected_bytes);
                }
                DataDrivenTest::TokenFailure(failure_case) => {
                    let amount_from_json = failure_case.test_json;

                    assert!(TokenValue::from_str(&amount_from_json.value).is_err());
                }
            }
        }
    }
}
