#![cfg(not(target_arch = "wasm32"))]

use url::Url;
use xrpl_lib::{
    address::Address,
    rpc::HttpRpcClient,
    testnet_faucet::TestnetFaucet,
    transaction::UnsignedPaymentTransaction,
    transaction_result::{TransactionResult, TransactionResultSuccess},
};

#[tokio::test]
async fn testnet_payment() {
    let faucet = TestnetFaucet::hooks_testnet_v3();
    let rpc = HttpRpcClient::new(Url::parse("https://hooks-testnet-v3.xrpl-labs.com/").unwrap());

    let new_account = faucet.get_new_account().await.unwrap();
    assert_eq!(
        new_account.address,
        new_account.secret.private_key().public_key().address()
    );

    let private_key = new_account.secret.private_key();

    let account_info = rpc.account_info(new_account.address).await.unwrap();

    let unsigned_payment = UnsignedPaymentTransaction {
        account: new_account.address,
        network_id: 21338,
        fee: 1000000000,
        sequence: account_info.account_data.sequence,
        signing_pub_key: private_key.public_key(),
        amount: 9000000000,
        destination: Address::from_base58check("rUUPx6MKAZbaR5zLmUcs9FRou3FhdKa2qD").unwrap(),
    };
    let signed_payment = unsigned_payment.sign(&private_key);

    let result = rpc.submit(&signed_payment.to_bytes()).await.unwrap();

    assert_eq!(
        TransactionResult::Success(TransactionResultSuccess::Success),
        result.engine_result
    );
}
