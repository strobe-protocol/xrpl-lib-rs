use reqwest::Client;
use serde::Deserialize;
use url::Url;

use crate::{address::Address, hash::Hash, secret::Secret, transaction_result::TransactionResult};

pub struct TestnetFaucet {
    http_client: Client,
    base_url: Url,
}

#[derive(Debug, thiserror::Error)]
pub enum TestnetFaucetError {
    #[error(transparent)]
    HttpError(reqwest::Error),
}

#[derive(Debug)]
pub struct NewAccountResult {
    pub secret: Secret,
    pub address: Address,
}

#[allow(unused)]
#[derive(Debug, Deserialize)]
struct NewAccountResponse {
    pub address: Address,
    pub secret: Secret,
    pub xrp: u64,
    pub hash: Hash,
    pub code: TransactionResult,
}

impl TestnetFaucet {
    pub fn new(base_url: Url) -> Self {
        Self {
            http_client: Client::new(),
            base_url,
        }
    }

    pub fn hooks_testnet_v3() -> Self {
        // Safe to unwrap since it's valid URL
        Self::new("https://hooks-testnet-v3.xrpl-labs.com".parse().unwrap())
    }

    pub async fn get_new_account(&self) -> Result<NewAccountResult, TestnetFaucetError> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .expect("invalid base URL")
            .extend(&["newcreds"]);

        let response = self
            .http_client
            .post(url)
            .send()
            .await
            .map_err(TestnetFaucetError::HttpError)?;

        let response: NewAccountResponse = response
            .json()
            .await
            .map_err(TestnetFaucetError::HttpError)?;

        Ok(NewAccountResult {
            secret: response.secret,
            address: response.address,
        })
    }
}
