use reqwest::Client as HttpClient;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::{address::Address, transaction_result::TransactionResult};

#[derive(Debug)]
pub struct HttpRpcClient {
    url: Url,
    client: HttpClient,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpRpcClientError {
    #[error(transparent)]
    HttpError(reqwest::Error),
    #[error("unsuccessful status code: {0}")]
    UnsuccessfulStatusCode(reqwest::StatusCode),
}

#[derive(Debug, Deserialize)]
pub struct SubmitResult {
    pub accepted: bool,
    pub engine_result: TransactionResult,
}

#[derive(Debug, Deserialize)]
pub struct AccountInfoResult {
    pub account_data: AccountData,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AccountData {
    pub sequence: u32,
}

#[derive(Debug, Serialize)]
struct RpcRequest<T> {
    method: RpcMethod,
    params: T,
}

#[derive(Debug, Deserialize)]
struct RpcResponse<T> {
    result: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RpcMethod {
    Submit,
    AccountInfo,
}

#[derive(Debug, Serialize)]
struct SubmitRequestParams<'a> {
    #[serde(serialize_with = "serialize_byte_slice_as_upper_hex")]
    tx_blob: &'a [u8],
}

#[derive(Debug, Serialize)]
struct AccountInfoRequestParam {
    account: Address,
    ledger_index: &'static str,
}

impl HttpRpcClient {
    pub fn new(url: Url) -> Self {
        Self::new_with_client(url, HttpClient::new())
    }

    pub fn new_with_client(url: Url, client: HttpClient) -> Self {
        Self { url, client }
    }

    pub async fn submit(&self, tx_blob: &[u8]) -> Result<SubmitResult, HttpRpcClientError> {
        self.send_rpc_request::<_, SubmitResult>(
            RpcMethod::Submit,
            &SubmitRequestParams { tx_blob },
        )
        .await
    }

    pub async fn account_info(
        &self,
        account: Address,
    ) -> Result<AccountInfoResult, HttpRpcClientError> {
        self.send_rpc_request::<_, AccountInfoResult>(
            RpcMethod::AccountInfo,
            &AccountInfoRequestParam {
                account,
                ledger_index: "current",
            },
        )
        .await
    }

    async fn send_rpc_request<REQ, RES>(
        &self,
        method: RpcMethod,
        request: &REQ,
    ) -> Result<RES, HttpRpcClientError>
    where
        REQ: Serialize,
        RES: DeserializeOwned,
    {
        let request = self.client.post(self.url.clone()).json(&RpcRequest {
            method,
            params: [request],
        });

        let response = request
            .send()
            .await
            .map_err(HttpRpcClientError::HttpError)?;

        let status_code = response.status();
        if !status_code.is_success() {
            return Err(HttpRpcClientError::UnsuccessfulStatusCode(status_code));
        }

        let body: RpcResponse<RES> = response
            .json()
            .await
            .map_err(HttpRpcClientError::HttpError)?;

        Ok(body.result)
    }
}

fn serialize_byte_slice_as_upper_hex<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(value).to_ascii_uppercase())
}
