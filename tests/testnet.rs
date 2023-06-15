#![cfg(not(target_arch = "wasm32"))]

use std::time::Duration;

use hex_literal::hex;
use url::Url;
use xrpl_lib::{
    address::Address,
    crypto::PrivateKey,
    rpc::HttpRpcClient,
    testnet_faucet::{NewAccountResult, TestnetFaucet, TestnetFaucetError},
    transaction::{Hook, UnsignedPaymentTransaction, UnsignedSetHookTransaction},
    transaction_result::{TransactionResult, TransactionResultSuccess},
};

struct CommonSetup {
    private_key: PrivateKey,
    address: Address,
    account_sequence: u32,
    rpc: HttpRpcClient,
}

async fn setup() -> CommonSetup {
    let faucet = TestnetFaucet::hooks_testnet_v3();
    let rpc = HttpRpcClient::new(Url::parse("https://hooks-testnet-v3.xrpl-labs.com/").unwrap());

    let new_account = get_new_account(&faucet).await;

    assert_eq!(
        new_account.address,
        new_account.secret.private_key().public_key().address()
    );

    let private_key = new_account.secret.private_key();

    let account_info = rpc.account_info(new_account.address).await.unwrap();

    CommonSetup {
        private_key,
        address: new_account.address,
        account_sequence: account_info.account_data.sequence,
        rpc,
    }
}

async fn get_new_account(faucet: &TestnetFaucet) -> NewAccountResult {
    let mut attempts = 0;

    let rate_limited_regex = regex::Regex::new("^you must wait (?P<seconds>\\d.)").unwrap();

    loop {
        match faucet.get_new_account().await {
            Ok(account) => break account,
            Err(TestnetFaucetError::ErrorMessage(err_msg)) => {
                if let Some(rate_limited_matches) = rate_limited_regex.captures(&err_msg) {
                    attempts += 1;
                    if attempts >= 50 {
                        panic!("still failing after {} attempts", attempts)
                    }

                    let seconds_to_wait: u64 = rate_limited_matches
                        .name("seconds")
                        .unwrap()
                        .as_str()
                        .parse()
                        .unwrap();

                    tokio::time::sleep(Duration::from_secs(seconds_to_wait)).await;
                } else {
                    panic!("unexpected faucet error message: {}", err_msg);
                }
            }
            _ => panic!("faucet request failure"),
        }
    }
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_payment() {
    let setup = setup().await;

    let unsigned_tx = UnsignedPaymentTransaction {
        account: setup.address,
        network_id: 21338,
        fee: 1000000000,
        sequence: setup.account_sequence,
        signing_pub_key: setup.private_key.public_key(),
        amount: 9000000000,
        destination: Address::from_base58check("rUUPx6MKAZbaR5zLmUcs9FRou3FhdKa2qD").unwrap(),
    };
    let signed_tx = unsigned_tx.sign(&setup.private_key);

    let result = setup.rpc.submit(&signed_tx.to_bytes()).await.unwrap();

    assert_eq!(
        TransactionResult::Success(TransactionResultSuccess::Success),
        result.engine_result
    );
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_set_hook() {
    let setup = setup().await;

    let unsigned_tx = UnsignedSetHookTransaction {
        account: setup.address,
        network_id: 21338,
        fee: 1000000000,
        sequence: setup.account_sequence,
        signing_pub_key: setup.private_key.public_key(),
        hooks: vec![Hook {
            hook_api_version: 0,
            hook_on: hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbffffe")
                .into(),
            hook_namespace: hex!(
                "0000000000000000000000000000000000000000000000000000000000000001"
            )
            .into(),
            create_code: include_bytes!("./data/hook-accept.wasm").to_vec(),
        }],
    };
    let signed_tx = unsigned_tx.sign(&setup.private_key);

    let result = setup.rpc.submit(&signed_tx.to_bytes()).await.unwrap();

    assert_eq!(
        TransactionResult::Success(TransactionResultSuccess::Success),
        result.engine_result
    );
}
