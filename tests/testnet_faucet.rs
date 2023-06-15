#![cfg(not(target_arch = "wasm32"))]

use xrpl_lib::testnet_faucet::TestnetFaucet;

#[tokio::test]
async fn testnet_faucet_new_account() {
    let faucet = TestnetFaucet::hooks_testnet_v3();

    let new_account = faucet.get_new_account().await.unwrap();

    assert_eq!(
        new_account.address,
        new_account.secret.private_key().public_key().address()
    );
}
