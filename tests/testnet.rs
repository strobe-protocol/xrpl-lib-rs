#![cfg(not(target_arch = "wasm32"))]

use std::{str::FromStr, time::Duration};

use bigdecimal::BigDecimal;
use hex_literal::hex;
use url::Url;
use xrpl_lib::{
    address::Address,
    amount::{Amount, TokenAmount, TokenValue, XrpAmount},
    crypto::PrivateKey,
    currency_code::{CurrencyCode, StandardCurrencyCode},
    hash::Hash,
    rpc::{
        AccountInfoError, AccountInfoResult, AccountLinesResult, AccountObjectLedgerEntryType,
        AccountObjectLedgerEntryTypeRequestParam, AccountObjectsResult, HookAccountObject,
        HttpRpcClient, LedgerEntryHookStateRequestParam, LedgerEntryNode, LedgerEntryResult,
        LedgerIndex, LedgerIndexShortcut, SubmitResult, Validation,
    },
    secret::Secret,
    testnet_faucet::{NewAccountResult, TestnetFaucet, TestnetFaucetError},
    transaction::{
        flags, Hook, HookParameter, UnsignedAccountSetTransaction, UnsignedInvokeTransaction,
        UnsignedPaymentTransaction, UnsignedSetHookTransaction, UnsignedTrustSetTransaction,
    },
    utils::{get_transaction_context, wait_for_transaction},
};

const HOOK_NAMESPACE: [u8; 32] =
    hex!("0000000000000000000000000000000000000000000000000000000000000001");

struct CommonSetup {
    private_key: PrivateKey,
    address: Address,
    rpc: HttpRpcClient,
}

async fn setup() -> CommonSetup {
    let faucet = TestnetFaucet::hooks_testnet_v3();
    let rpc = HttpRpcClient::new(
        Url::parse("https://hooks-testnet-v3.xrpl-labs.com/").unwrap(),
        10000,
    );

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

        let account_info = rpc
            .account_info(
                new_account.address,
                LedgerIndex::Shortcut(LedgerIndexShortcut::Validated),
            )
            .await
            .expect("failed to get account info");

        match account_info {
            AccountInfoResult::Success(account_info) => {
                assert!(account_info.validated);

                return CommonSetup {
                    private_key,
                    address: new_account.address,
                    rpc,
                };
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
            Err(err) => {
                attempts += 1;
                if attempts >= 50 {
                    panic!("still failing after {} attempts", attempts)
                }

                match err {
                    TestnetFaucetError::ErrorMessage(err_msg) => {
                        if let Some(rate_limited_matches) = rate_limited_regex.captures(&err_msg) {
                            let seconds_to_wait: u64 = rate_limited_matches
                                .name("seconds")
                                .unwrap()
                                .as_str()
                                .parse()
                                .unwrap_or_else(|_| {
                                    panic!("failed to parse seconds from: '{}'", err_msg)
                                });

                            tokio::time::sleep(Duration::from_secs(seconds_to_wait)).await;
                        } else {
                            panic!("unexpected faucet error message: {}", err_msg);
                        }
                    }
                    _ => {
                        // Unknown error. Simply retry after 5 seconds
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                }
            }
        }
    }
}

async fn set_hook(setup: &CommonSetup, hook_on: Hash, create_code: Vec<u8>) {
    let txn_ctx = get_transaction_context(setup.address, &setup.rpc)
        .await
        .unwrap();
    let unsigned_tx = UnsignedSetHookTransaction {
        account: setup.address,
        network_id: 21338,
        fee: XrpAmount::from_drops(1000000000).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: setup.private_key.public_key(),
        hook_parameters: None,
        hooks: vec![Hook {
            hook_api_version: 0,
            hook_on,
            hook_namespace: HOOK_NAMESPACE.into(),
            create_code,
            hook_parameters: vec![],
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
            Some(AccountObjectLedgerEntryTypeRequestParam::Hook),
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
async fn testnet_xrp_payment() {
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

    let txn_ctx = get_transaction_context(benefactor.address, &benefactor.rpc)
        .await
        .unwrap();
    let unsigned_tx = UnsignedPaymentTransaction {
        account: benefactor.address,
        network_id: 21338,
        fee: XrpAmount::from_drops(payment_fee).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: benefactor.private_key.public_key(),
        hook_parameters: None,
        amount: Amount::Xrp(XrpAmount::from_drops(payment_amount).unwrap()),
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
async fn testnet_account_set() {
    let setup = setup().await;

    let txn_ctx = get_transaction_context(setup.address, &setup.rpc)
        .await
        .unwrap();

    let unsigned_tx = UnsignedAccountSetTransaction {
        account: setup.address,
        network_id: 21338,
        flags: vec![
            flags::AccountSetTfFlags::DisallowXRP,
            flags::AccountSetTfFlags::RequireDestTag,
        ],
        set_flag: Some(flags::AccountSetAsfFlags::RequireAuth),
        fee: XrpAmount::from_drops(100).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: setup.private_key.public_key(),
        hook_parameters: None,
    };

    let signed_tx = unsigned_tx.sign(&setup.private_key);

    let account_set_result = setup
        .rpc
        .submit(&signed_tx.to_bytes())
        .await
        .expect("failed to submit payment");

    match account_set_result {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &setup.rpc)
                .await
                .expect("failed to wait for transaction");

            assert_eq!(signed_tx.hash(), validated_tx.hash);
            assert_eq!(setup.address, validated_tx.account);
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_trust_set() {
    let setup = setup().await;

    let txn_ctx = get_transaction_context(setup.address, &setup.rpc)
        .await
        .unwrap();

    let unsigned_tx = UnsignedTrustSetTransaction {
        account: setup.address,
        network_id: 21338,
        flags: vec![flags::TrustSetFlags::SetFreeze],
        fee: XrpAmount::from_drops(100).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: setup.private_key.public_key(),
        limit_amount: TokenAmount {
            value: "100".parse().unwrap(),
            currency: CurrencyCode::Standard(StandardCurrencyCode::new(*b"BTC").unwrap()),
            issuer: Address::from_base58check("rhsFZHhNUDwiRGj7arkKAyQrRaK11cmwc8").unwrap(),
        },
    };

    let signed_tx = unsigned_tx.sign(&setup.private_key);

    let trust_set_result = setup
        .rpc
        .submit(&signed_tx.to_bytes())
        .await
        .expect("failed to submit trust set");

    match trust_set_result {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &setup.rpc)
                .await
                .expect("failed to wait for transaction");

            assert_eq!(signed_tx.hash(), validated_tx.hash);
            assert_eq!(setup.address, validated_tx.account);
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_hook_execution() {
    let beneficiary = setup().await;

    set_hook(
        &beneficiary,
        hex!("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbffffe").into(),
        include_bytes!("./data/hook-accept.wasm").to_vec(),
    )
    .await;

    let beneficiary_hook_object = get_account_hook_object(&beneficiary).await;

    let benefactor = setup().await;
    let txn_ctx = get_transaction_context(benefactor.address, &beneficiary.rpc)
        .await
        .unwrap();

    let unsigned_tx = UnsignedPaymentTransaction {
        account: benefactor.address,
        network_id: 21338,
        fee: XrpAmount::from_drops(100000000).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: benefactor.private_key.public_key(),
        hook_parameters: None,
        amount: Amount::Xrp(XrpAmount::from_drops(1000000).unwrap()),
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

            match validated_tx.validation {
                Validation::Validated(meta) => {
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
                    assert_eq!(hook_execution_holder.hook_execution.hook_emit_count, 0);
                    assert_eq!(hook_execution_holder.hook_execution.hook_return_string, b"");
                }
                _ => panic!("transaction metadata is missing"),
            }
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_tt_invoke_hook_execution_with_hook_parameters() {
    let hook_account = setup().await;

    set_hook(
        &hook_account,
        hex!("fffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffbfffff").into(),
        include_bytes!("./data/hook-on-tt-invoke.wasm").to_vec(),
    )
    .await;
    let hook_account_hook_object = get_account_hook_object(&hook_account).await;

    let invoker = setup().await;
    let txn_ctx = get_transaction_context(invoker.address, &hook_account.rpc)
        .await
        .unwrap();

    let unsigned_tx = UnsignedInvokeTransaction {
        account: invoker.address,
        network_id: 21338,
        flags: 0,
        fee: XrpAmount::from_drops(100000000).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: invoker.private_key.public_key(),
        hook_parameters: Some(vec![
            HookParameter {
                name: "test".into(),
                value: "test value".into(),
            },
            HookParameter {
                name: "test1".into(),
                value: "test value1".into(),
            },
        ]),
        destination: hook_account.address,
    };
    let signed_tx = unsigned_tx.sign(&invoker.private_key);

    let invoke_result = invoker
        .rpc
        .submit(&signed_tx.to_bytes())
        .await
        .expect("failed to submit payment tx");

    match invoke_result {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &invoker.rpc)
                .await
                .expect("failed to wait for transaction");

            assert_eq!(signed_tx.hash(), validated_tx.hash);
            assert_eq!(invoker.address, validated_tx.account);

            match validated_tx.validation {
                Validation::Validated(meta) => {
                    let hook_executions = meta
                        .hook_executions
                        .expect("hook executions are missing from transaction metadata");

                    assert_eq!(hook_executions.len(), 1);

                    let hook_execution_holder = &hook_executions[0];

                    assert_eq!(
                        hook_execution_holder.hook_execution.hook_account,
                        hook_account.address
                    );
                    assert_eq!(
                        hook_account_hook_object.hook_hash,
                        hook_execution_holder.hook_execution.hook_hash
                    );
                    assert!(hook_execution_holder.hook_execution.hook_return_code >= 0);
                    assert_eq!(hook_execution_holder.hook_execution.hook_emit_count, 0);

                    let expected_hook_return_string = b"hook_on_tt: Finished.\x00";
                    assert_eq!(
                        hook_execution_holder.hook_execution.hook_return_string,
                        expected_hook_return_string
                    );
                }
                _ => panic!("transaction metadata is missing"),
            }
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }
}
#[tokio::test]
#[ignore = "skipped by default as RPC is rate limited"]
async fn testnet_account_lines() {
    let rpc = HttpRpcClient::new(
        Url::parse("https://hooks-testnet-v3.xrpl-labs.com/").unwrap(),
        10000,
    );

    let lines = rpc
        .account_lines(
            Address::from_base58check("r4UniHrv3rvnqoqStn8co7PmXN112NMimX").unwrap(),
            LedgerIndex::Shortcut(LedgerIndexShortcut::Validated),
            None,
        )
        .await
        .unwrap();

    let lines = match lines {
        AccountLinesResult::Success(value) => value,
        AccountLinesResult::Error(rpc_error) => {
            panic!("failed to fetch account lines: {:?}", rpc_error.error)
        }
    };

    assert!(lines.lines.len() > 1);
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_hook_ledger_entry() {
    let hook_account = setup().await;

    set_hook(
        &hook_account,
        hex!("fffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffbfffff").into(),
        include_bytes!("./data/hook-state.wasm").to_vec(),
    )
    .await;
    let hook_account_hook_object = get_account_hook_object(&hook_account).await;
    let invoker = setup().await;
    let txn_ctx = get_transaction_context(invoker.address, &hook_account.rpc)
        .await
        .unwrap();

    let unsigned_tx = UnsignedInvokeTransaction {
        account: invoker.address,
        network_id: 21338,
        flags: 0,
        fee: XrpAmount::from_drops(100000000).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: invoker.private_key.public_key(),
        hook_parameters: None,
        destination: hook_account.address,
    };
    let signed_tx = unsigned_tx.sign(&invoker.private_key);

    let invoke_result = invoker
        .rpc
        .submit(&signed_tx.to_bytes())
        .await
        .expect("failed to submit tx");

    match invoke_result {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &invoker.rpc)
                .await
                .expect("failed to wait for transaction");

            assert_eq!(signed_tx.hash(), validated_tx.hash);
            assert_eq!(invoker.address, validated_tx.account);

            match validated_tx.validation {
                Validation::Validated(meta) => {
                    let hook_executions = meta
                        .hook_executions
                        .expect("hook executions are missing from transaction metadata");

                    assert_eq!(hook_executions.len(), 1);

                    let hook_execution_holder = &hook_executions[0];

                    assert_eq!(
                        hook_execution_holder.hook_execution.hook_account,
                        hook_account.address
                    );
                    assert_eq!(
                        hook_account_hook_object.hook_hash,
                        hook_execution_holder.hook_execution.hook_hash
                    );
                    assert!(hook_execution_holder.hook_execution.hook_return_code >= 0);
                    assert_eq!(hook_execution_holder.hook_execution.hook_emit_count, 0);

                    let hook_account_address_bytes = hook_account.address.to_bytes();
                    let mut padded_hook_account_address_bytes = [0; 32];
                    padded_hook_account_address_bytes[12..].copy_from_slice(
                        &hook_account_address_bytes[..hook_account_address_bytes.len()],
                    );

                    let hook_state_ledger_entry = hook_account
                        .rpc
                        .ledger_entry(LedgerEntryHookStateRequestParam {
                            account: hook_account.address,
                            key: padded_hook_account_address_bytes.to_vec(),
                            namespace_id: HOOK_NAMESPACE.to_vec(),
                        })
                        .await
                        .expect("failed to get hook state ledger entry");

                    match hook_state_ledger_entry {
                        LedgerEntryResult::Success(success) => match success.node {
                            LedgerEntryNode::HookState(node) => {
                                let mut reversed_state_data = node.hook_state_data.clone();
                                reversed_state_data.reverse();
                                assert_eq!(reversed_state_data, hex!("000000000000000C"));
                            }
                            _ => {
                                panic!("unexpected ledger entry type");
                            }
                        },
                        LedgerEntryResult::Error(error) => {
                            panic!("failed to get hook state ledger entry: {:?}", error.error);
                        }
                    }
                }
                _ => panic!("transaction metadata is missing"),
            }
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }
}

#[tokio::test]
#[ignore = "skipped by default as access to faucet is rate limited"]
async fn testnet_issue_fungible_token() {
    let setup = setup().await;

    let beneficiary_address = setup.address;
    let beneficiary_private_key = setup.private_key;

    let issuer_secret = Secret::from_base58check("ship7q694kpbauat3ZeaAyo3dimmB").unwrap();
    let issuer_address = issuer_secret.private_key().public_key().address();

    let txn_ctx = get_transaction_context(issuer_address, &setup.rpc)
        .await
        .unwrap();
    let issuer_account_set_tx = UnsignedAccountSetTransaction {
        account: issuer_address,
        network_id: 21338,
        flags: vec![],
        set_flag: Some(flags::AccountSetAsfFlags::DefaultRipple),
        fee: XrpAmount::from_drops(100).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: issuer_secret.private_key().public_key(),
        hook_parameters: None,
    };
    let issuer_account_set_signed_tx = issuer_account_set_tx.sign(&issuer_secret.private_key());
    let issuer_account_set_tx = setup
        .rpc
        .submit(&issuer_account_set_signed_tx.to_bytes())
        .await
        .expect("failed to submit AccountSet tx");

    match issuer_account_set_tx {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &setup.rpc)
                .await
                .expect("failed to wait for transaction");
            assert_eq!(issuer_account_set_signed_tx.hash(), validated_tx.hash);
            assert_eq!(issuer_address, validated_tx.account);
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }

    let txn_ctx = get_transaction_context(beneficiary_address, &setup.rpc)
        .await
        .unwrap();
    let beneficiary_account_set_tx = UnsignedAccountSetTransaction {
        account: beneficiary_address,
        network_id: 21338,
        flags: vec![],
        set_flag: None,
        fee: XrpAmount::from_drops(100).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: beneficiary_private_key.public_key(),
        hook_parameters: None,
    };
    let beneficiary_account_set_signed_tx =
        beneficiary_account_set_tx.sign(&beneficiary_private_key);
    let beneficiary_account_set_tx = setup
        .rpc
        .submit(&beneficiary_account_set_signed_tx.to_bytes())
        .await
        .expect("failed to submit AccountSet tx");

    match beneficiary_account_set_tx {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &setup.rpc)
                .await
                .expect("failed to wait for transaction");
            assert_eq!(beneficiary_account_set_signed_tx.hash(), validated_tx.hash);
            assert_eq!(beneficiary_address, validated_tx.account);
        }
        SubmitResult::Error(error) => {
            panic!("failed to submit transaction: {:?}", error.error)
        }
    }

    let txn_ctx = get_transaction_context(beneficiary_address, &setup.rpc)
        .await
        .unwrap();
    let unsigned_trust_set_tx = UnsignedTrustSetTransaction {
        account: beneficiary_address,
        network_id: 21338,
        flags: vec![],
        fee: XrpAmount::from_drops(100).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: beneficiary_private_key.public_key(),
        limit_amount: TokenAmount {
            value: TokenValue::from_str("1000000000000000").unwrap(),
            currency: CurrencyCode::Standard(StandardCurrencyCode::new(*b"MMM").unwrap()),
            issuer: issuer_address,
        },
    };

    let trust_set_signed_tx: xrpl_lib::transaction::SignedTrustSetTransaction =
        unsigned_trust_set_tx.sign(&beneficiary_private_key);

    let trust_set_result = setup
        .rpc
        .submit(&trust_set_signed_tx.to_bytes())
        .await
        .expect("failed to submit TrustSet tx");

    match trust_set_result {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &setup.rpc)
                .await
                .expect("failed to wait for transaction");

            assert_eq!(trust_set_signed_tx.hash(), validated_tx.hash);
            assert_eq!(beneficiary_address, validated_tx.account);
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }

    let txn_ctx = get_transaction_context(issuer_address, &setup.rpc)
        .await
        .expect("failed to prepare for transaction");
    let unsigned_token_issue_payment_tx = UnsignedPaymentTransaction {
        account: issuer_address,
        network_id: 21338,
        fee: XrpAmount::from_drops(100).unwrap(),
        sequence: txn_ctx.account_sequence,
        last_ledger_sequence: txn_ctx.last_ledger_sequence,
        signing_pub_key: issuer_secret.private_key().public_key(),
        hook_parameters: None,
        amount: Amount::Token(TokenAmount {
            value: TokenValue::from_str("10").unwrap(),
            currency: CurrencyCode::Standard(StandardCurrencyCode::new(*b"MMM").unwrap()),
            issuer: issuer_address,
        }),
        destination: beneficiary_address,
    };

    let token_issue_payment_signed_tx =
        unsigned_token_issue_payment_tx.sign(&issuer_secret.private_key());
    let token_issue_payment_result = setup
        .rpc
        .submit(&token_issue_payment_signed_tx.to_bytes())
        .await
        .expect("failed to submit payment tx");

    match token_issue_payment_result {
        SubmitResult::Success(submit_success) => {
            let validated_tx = wait_for_transaction(submit_success.tx_json.hash, &setup.rpc)
                .await
                .expect("failed to wait for transaction");

            assert_eq!(token_issue_payment_signed_tx.hash(), validated_tx.hash);
            assert_eq!(issuer_address, validated_tx.account);
        }
        SubmitResult::Error(rpc_error) => {
            panic!("failed to submit transaction: {:?}", rpc_error.error)
        }
    }

    let account_lines = setup
        .rpc
        .account_lines(
            beneficiary_address,
            LedgerIndex::Shortcut(LedgerIndexShortcut::Validated),
            Some(issuer_address),
        )
        .await
        .expect("failed to get account lines");

    match account_lines {
        AccountLinesResult::Success(success) => {
            let fake_token_line = success.lines.first().expect("no account lines found");
            assert_eq!(
                Into::<BigDecimal>::into(fake_token_line.balance.clone()),
                BigDecimal::from_str("10.0").unwrap()
            );
            assert_eq!(fake_token_line.account, issuer_address);
            assert_eq!(
                fake_token_line.currency,
                CurrencyCode::Standard(StandardCurrencyCode::new(*b"MMM").unwrap())
            );
        }
        AccountLinesResult::Error(rpc_error) => {
            panic!("failed to get account lines: {:?}", rpc_error.error)
        }
    }
}
