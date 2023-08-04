use serde::Deserialize;

use xrpl_lib::amount::{Amount, TokenAmount, XrpAmount};

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

#[derive(Debug, Deserialize)]
struct TestData {
    values_tests: Vec<DataDrivenTest>,
}

#[test]
fn test_amount_to_bytes() {
    let json_str = include_str!("./data/data-driven-tests.json");
    let data: TestData = serde_json::from_str(json_str).unwrap();

    for test_case in data.values_tests {
        match test_case {
            DataDrivenTest::XrpSuccess(xrp_test_case) => {
                let amount_from_bytes = XrpAmount::from_byte_slice(
                    &hex::decode(xrp_test_case.expected_hex.clone()).unwrap(),
                )
                .expect("Failed to create amount from bytes");

                assert_eq!(
                    amount_from_bytes.to_bytes(),
                    hex::decode(xrp_test_case.expected_hex.clone()).unwrap()
                );

                let amount_from_json = xrp_test_case.test_json;
                assert_eq!(
                    Amount::from_drops(amount_from_json.parse::<u64>().unwrap())
                        .expect("failed to parse drops")
                        .to_bytes(),
                    hex::decode(xrp_test_case.expected_hex).unwrap()
                );
            }
            DataDrivenTest::XrpFailure(xrp_test_case) => {
                let amount_from_json = xrp_test_case.test_json;
                assert!(Amount::from_drops(amount_from_json.parse::<u64>().unwrap()).is_err());
            }
            DataDrivenTest::TokenSuccess(success_case) => {
                let amount_from_json = success_case.test_json;

                let amount_from_bytes = TokenAmount::from_byte_slice(
                    &hex::decode(success_case.expected_hex.clone()).unwrap(),
                )
                .expect("Failed to create amount from bytes");

                assert_eq!(
                    amount_from_bytes.to_bytes(),
                    hex::decode(success_case.expected_hex.clone()).unwrap()
                );

                let amount = Amount::from_strings(
                    &amount_from_json.value,
                    &amount_from_json.currency,
                    &amount_from_json.issuer,
                )
                .expect("failed to parse token amount");

                let expected_bytes = hex::decode(success_case.expected_hex).unwrap();
                assert_eq!(amount.to_bytes(), expected_bytes);
            }
            DataDrivenTest::TokenFailure(failure_case) => {
                let amount_from_json = failure_case.test_json;

                assert!(Amount::from_strings(
                    &amount_from_json.value,
                    &amount_from_json.currency,
                    &amount_from_json.issuer,
                )
                .is_err());
            }
        }
    }
}
