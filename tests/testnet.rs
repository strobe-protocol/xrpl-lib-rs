#![cfg(not(target_arch = "wasm32"))]

use std::time::Duration;

use hex_literal::hex;
use url::Url;
use xrpl_lib::{
    address::Address,
    crypto::PrivateKey,
    rpc::{
        AccountInfoError, AccountInfoResult, AccountObjectLedgerEntryType, AccountObjectsResult,
        HookAccountObject, HttpRpcClient, LedgerIndex, LedgerIndexShortcut, LedgerResult,
        SubmitResult,
    },
    testnet_faucet::{NewAccountResult, TestnetFaucet, TestnetFaucetError},
    transaction::{Hook, UnsignedPaymentTransaction, UnsignedSetHookTransaction},
    utils::{create_last_ledger_sequence, wait_for_transaction},
};

struct CommonSetup {
    private_key: PrivateKey,
    address: Address,
    account_sequence: u32,
    rpc: HttpRpcClient,
    last_validated_ledger_index: u32,
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
    let mut attempts = 0;

    loop {
        if attempts >= 3 {
            panic!(
                "failed to get a validated account within {} attempts",
                attempts
            )
        }

        attempts += 1;

        let (account_info_result, last_validated_ledger_result) = tokio::join!(
            rpc.account_info(
                new_account.address,
                LedgerIndex::Shortcut(LedgerIndexShortcut::Validated)
            ),
            rpc.ledger(LedgerIndex::Shortcut(LedgerIndexShortcut::Validated))
        );
        let account_info = account_info_result.expect("failed to get account info");
        let last_validated_ledger =
            last_validated_ledger_result.expect("failed to get last validated ledger");

        match account_info {
            AccountInfoResult::Success(account_info) => {
                assert!(account_info.validated);

                match last_validated_ledger {
                    LedgerResult::Success(ledger_success) => {
                        return CommonSetup {
                            private_key,
                            address: new_account.address,
                            account_sequence: account_info.account_data.sequence,
                            last_validated_ledger_index: ledger_success.ledger_index,
                            rpc,
                        };
                    }
                    LedgerResult::Error(ledger_error) => {
                        panic!("unexpected ledger error: {:?}", ledger_error.error)
                    }
                }
            }
            AccountInfoResult::Error(err) => match err.error {
                // If the account is not found, wait for the ledger to find and validate the account
                AccountInfoError::ActNotFound => {}
                _ => panic!("unexpected account info error: {:?}", err),
            },
        }
        tokio::time::sleep(Duration::from_millis(3000)).await;
    }
}

async fn get_new_account(faucet: &TestnetFaucet) -> NewAccountResult {
    let mut attempts = 0;

    let rate_limited_regex =
        regex::Regex::new("^you must wait (?P<seconds>\\d+) seconds before requesting again$")
            .unwrap();

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
                        .unwrap_or_else(|_| panic!("failed to parse seconds from: '{}'", err_msg));

                    tokio::time::sleep(Duration::from_secs(seconds_to_wait)).await;
                } else {
                    panic!("unexpected faucet error message: {}", err_msg);
                }
            }
            _ => panic!("faucet request failure"),
        }
    }
}

async fn set_hook(setup: &CommonSetup) {
    let unsigned_tx = UnsignedSetHookTransaction {
        account: setup.address,
        network_id: 21338,
        fee: 1000000000,
        sequence: setup.account_sequence,
        last_ledger_sequence: create_last_ledger_sequence(setup.last_validated_ledger_index),
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
    let set_hook_result = setup
        .rpc
        .submit(&signed_tx.to_bytes())
        .await
        .expect("failed to submit SetHook transaction");

    match set_hook_result {
        SubmitResult::Success(transaction_result_success) => {
            let validated_tx =
                wait_for_transaction(transaction_result_success.tx_json.hash, &setup.rpc)
                    .await
                    .expect("failed to wait for transaction");
            assert_eq!(signed_tx.hash(), validated_tx.hash);
            assert_eq!(setup.address, validated_tx.account);
        }
        SubmitResult::Error(transaction_result_error) => {
            panic!(
                "failed to submit transaction: {:?}",
                transaction_result_error.error
            )
        }
    }
}

async fn get_account_hook_object(setup: &CommonSetup) -> HookAccountObject {
    let account_objects_result = setup
        .rpc
        .account_objects(
            setup.address,
            LedgerIndex::Shortcut(LedgerIndexShortcut::Validated),
        )
        .await
        .expect("failed to get account objects");

    match account_objects_result {
        AccountObjectsResult::Success(account_objects_success) => {
            assert!(account_objects_success.validated);
            assert_eq!(account_objects_success.account_objects.len(), 1);

            let maybe_hook_object = &account_objects_success.account_objects[0];
            assert_eq!(
                maybe_hook_object.ledger_entry_type,
                AccountObjectLedgerEntryType::Hook
            );

            let hooks = maybe_hook_object
                .hooks
                .as_ref()
                .expect("account objects don't contain the deployed hook");

            assert_eq!(hooks.len(), 1);

            let hook_holder = &hooks[0];

            hook_holder.hook.clone()
        }
        AccountObjectsResult::Error(account_objects_error) => {
            panic!(
                "failed to get account objects: {:?}",
                account_objects_error.error
            )
        }
    }
}

async fn get_account_balance(rpc: &HttpRpcClient, address: Address) -> u64 {
    let account_info_result = rpc
        .account_info(
            address,
            LedgerIndex::Shortcut(LedgerIndexShortcut::Validated),
        )
        .await
        .expect("failed to get account info");
    match account_info_result {
        AccountInfoResult::Success(account_info_success) => {
            account_info_success.account_data.balance
        }
        AccountInfoResult::Error(account_info_error) => {
            panic!("failed to get account info: {:?}", account_info_error.error)
        }
    }
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_payment() {
    let benefactor = setup().await;

    let beneficiary_address =
        Address::from_base58check("rsyyQ3ce4muSQrh14URqCWwWngzuotGhVP").unwrap();
    let (benefactor_balance_before, beneficiary_balance_before) = tokio::join!(
        get_account_balance(&benefactor.rpc, benefactor.address),
        get_account_balance(&benefactor.rpc, beneficiary_address)
    );
    assert_eq!(benefactor_balance_before, 10000000000);

    let payment_fee = 1000000000;
    let payment_amount = 9000000000;
    let expected_benefactor_balance_after =
        benefactor_balance_before - payment_fee - payment_amount;
    let expected_beneficiary_balance_after = beneficiary_balance_before + payment_amount;

    let unsigned_tx = UnsignedPaymentTransaction {
        account: benefactor.address,
        network_id: 21338,
        fee: payment_fee,
        sequence: benefactor.account_sequence,
        last_ledger_sequence: create_last_ledger_sequence(benefactor.last_validated_ledger_index),
        signing_pub_key: benefactor.private_key.public_key(),
        amount: payment_amount,
        destination: beneficiary_address,
    };
    let signed_tx = unsigned_tx.sign(&benefactor.private_key);

    let payment_result = benefactor
        .rpc
        .submit(&signed_tx.to_bytes())
        .await
        .expect("failed to submit payment");

    match payment_result {
        SubmitResult::Success(transaction_result_success) => {
            let validated_tx =
                wait_for_transaction(transaction_result_success.tx_json.hash, &benefactor.rpc)
                    .await
                    .expect("failed to wait for transaction");
            assert_eq!(signed_tx.hash(), validated_tx.hash);
            assert_eq!(benefactor.address, validated_tx.account);

            let (benefactor_balance_after, beneficiary_balance_after) = tokio::join!(
                get_account_balance(&benefactor.rpc, benefactor.address),
                get_account_balance(&benefactor.rpc, beneficiary_address)
            );

            assert_eq!(benefactor_balance_after, expected_benefactor_balance_after);
            assert_eq!(
                beneficiary_balance_after,
                expected_beneficiary_balance_after
            );
        }
        SubmitResult::Error(transaction_result_error) => {
            panic!(
                "failed to submit transaction: {:?}",
                transaction_result_error.error
            )
        }
    }
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_hook_execution() {
    let beneficiary = setup().await;

    set_hook(&beneficiary).await;

    let beneficiary_hook_object = get_account_hook_object(&beneficiary).await;

    let benefactor = setup().await;

    let unsigned_tx = UnsignedPaymentTransaction {
        account: benefactor.address,
        network_id: 21338,
        fee: 100000000,
        sequence: benefactor.account_sequence,
        last_ledger_sequence: create_last_ledger_sequence(benefactor.last_validated_ledger_index),
        signing_pub_key: benefactor.private_key.public_key(),
        amount: 1000000,
        destination: beneficiary.address,
    };
    let signed_tx = unsigned_tx.sign(&benefactor.private_key);

    let payment_result = benefactor
        .rpc
        .submit(&signed_tx.to_bytes())
        .await
        .expect("failed to submit payment tx");

    match payment_result {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &benefactor.rpc)
                .await
                .expect("failed to wait for transaction");

            assert_eq!(signed_tx.hash(), validated_tx.hash);
            assert_eq!(benefactor.address, validated_tx.account);

            let meta = validated_tx.meta.expect("meta is missing from transaction");
            let hook_executions = meta
                .hook_executions
                .expect("hook executions are missing from transaction metadata");

            assert_eq!(hook_executions.len(), 1);

            let hook_execution_holder = &hook_executions[0];

            assert_eq!(
                hook_execution_holder.hook_execution.hook_account,
                beneficiary.address
            );
            assert_eq!(
                beneficiary_hook_object.hook_hash,
                hook_execution_holder.hook_execution.hook_hash
            );
            assert!(hook_execution_holder.hook_execution.hook_return_code >= 0);
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }
}
