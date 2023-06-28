use reqwest::Client as HttpClient;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

use crate::{address::Address, hash::Hash, transaction_result::TransactionResult};

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
    #[error(transparent)]
    UniversalError(UniversalXrplError),
}

#[derive(Debug, Deserialize, thiserror::Error)]
pub enum UniversalXrplError {
    /// The server is amendment blocked and needs to be updated to the latest version to stay
    /// synced with the XRP Ledger network.
    #[serde(rename = "amendmentBlocked")]
    AmendmentBlocked,
    /// The server does not support the API version number from the request.
    #[serde(rename = "invalidApiVersion")]
    InvalidApiVersion,
    /// The server does not have a closed ledger, typically because it has not finished starting
    /// up.
    #[serde(rename = "noClosed")]
    NoClosed,
    /// The server does not know what the current ledger is, due to high load, network problems,
    /// validator failures, incorrect configuration, or some other problem.
    #[serde(rename = "noCurrent")]
    NoCurrent,
    /// The server is having trouble connecting to the rest of the XRP Ledger peer-to-peer network
    /// (and is not running in stand-alone mode).
    #[serde(rename = "noNetwork")]
    NoNetwork,
    /// The server is under too much load to do this command right now. Generally not returned if
    /// you are connected as an admin.
    #[serde(rename = "tooBusy")]
    TooBusy,
    /// The request does not contain a command that the rippled server recognizes.
    #[serde(rename = "unknownCmd")]
    UnknownCmd,
}

#[derive(Debug, Deserialize)]
pub enum LedgerError {
    /// The ledger specified by the ledger_hash or ledger_index does not exist, or it does exist
    /// but the server does not have it.
    #[serde(rename = "lgrNotFound")]
    LgrNotFound,
    /// If you specified full or accounts as true, but are not connected to the server as an admin
    /// (usually, admin requires connecting on a local port).
    #[serde(rename = "noPermission")]
    NoPermission,
}

#[derive(Debug, Deserialize)]
pub struct LedgerSuccess {
    pub ledger_index: u32,
    pub validated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum LedgerResult {
    Success(LedgerSuccess),
    Error(RpcError<LedgerError>),
}

#[derive(Debug, Deserialize)]
pub enum SubmitError {
    /// The fee_mult_max parameter was specified, but the server's current fee multiplier
    /// exceeds the specified one. (Sign-and-Submit mode only)
    #[serde(rename = "highFee")]
    HighFee,
    /// An internal error occurred when serializing the transaction to JSON. This
    /// could be caused by many aspects of the transaction, including a bad signature or some
    /// fields being malformed.
    #[serde(rename = "internalJson")]
    InternalJson,
    /// An internal error occurred when submitting the transaction. This could be
    /// caused by many aspects of the transaction, including a bad signature or some fields being
    /// malformed.
    #[serde(rename = "internalSubmit")]
    InternalSubmit,
    /// An internal error occurred when processing the transaction. This
    /// could be caused by many aspects of the transaction, including a bad signature or some
    /// fields being malformed.
    #[serde(rename = "internalTransaction")]
    InternalTransaction,
    /// One or more fields are specified incorrectly, or one or more required
    /// fields are missing.
    #[serde(rename = "invalidParams")]
    InvalidParams,
    /// The transaction is malformed or otherwise invalid.
    #[serde(rename = "invalidTransaction")]
    InvalidTransaction,
    /// The transaction did not include paths, and the server was unable to find a path by
    /// which this payment can occur. (Sign-and-Submit mode only)
    #[serde(rename = "noPath")]
    NoPath,
    /// Signing is not supported by this server (Sign-and-Submit mode only.) If you
    /// are the server admin, you can still access signing when connected as an admin, or you could
    /// enable public signing. New in: rippled 1.1.0
    #[serde(rename = "notSupported")]
    NotSupported,
}

#[derive(Debug, Deserialize)]
pub struct TxJson {
    pub hash: Hash,
}

#[derive(Debug, Deserialize)]
pub struct SubmitSuccess {
    pub tx_json: TxJson,
    pub engine_result: TransactionResult,
    pub validated_ledger_index: u32,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum SubmitResult {
    Success(SubmitSuccess),
    Error(RpcError<SubmitError>),
}

#[derive(Debug, Deserialize, Clone)]
pub enum AccountInfoError {
    /// The address specified in the account field of the request does not correspond to an account
    /// in the ledger.
    #[serde(rename = "actNotFound")]
    ActNotFound,
    /// The ledger specified by the ledger_hash or ledger_index does not exist, or it does exist
    /// but the server does not have it.
    #[serde(rename = "lgrNotFound")]
    LgrNotFound,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AccountData {
    pub sequence: u32,
}

#[derive(Debug, Deserialize)]
pub struct AccountInfoSuccess {
    pub account_data: AccountData,
    /// True if this data is from a validated ledger version; if omitted or set to false, this data
    /// is not final.
    #[serde(default = "bool::default")]
    pub validated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AccountInfoResult {
    Success(AccountInfoSuccess),
    Error(RpcError<AccountInfoError>),
}

#[derive(Debug, Deserialize)]
pub enum TxError {
    /// Either the transaction does not exist, or it was part of an ledger version that rippled
    /// does not have available.
    #[serde(rename = "txnNotFound")]
    TxnNotFound,
    /// The min_ledger and max_ledger fields of the request are more than 1000 apart.
    #[serde(rename = "excessiveLgrRange")]
    ExcessiveLgrRange,
    /// The specified min_ledger is larger than the max_ledger, or one of those parameters is not a
    /// valid ledger index.
    #[serde(rename = "invalidLgrRange")]
    InvalidLgrRange,
}

#[derive(Debug, Deserialize)]
pub struct TxSuccess {
    #[serde(rename = "Account")]
    pub account: Address,
    pub hash: Hash,
    /// If true, this data comes from a validated ledger version; if omitted or set to false, this
    /// data is not final.
    #[serde(default = "bool::default")]
    pub validated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TxResult {
    Success(TxSuccess),
    Error(RpcError<TxError>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LedgerIndexShortcut {
    Current,
    Closed,
    Validated,
}

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum LedgerIndex {
    Hash(Hash),
    Index(u32),
    Shortcut(LedgerIndexShortcut),
}

#[derive(Debug, Deserialize)]
pub struct RpcError<T> {
    pub error: T,
}

#[derive(Debug, Serialize)]
struct RpcRequest<T> {
    method: RpcMethod,
    params: T,
}

#[derive(Debug, Deserialize)]
struct RpcBaseResponse<T> {
    result: T,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RpcResponse<T> {
    Success(RpcBaseResponse<T>),
    Error(RpcBaseResponse<RpcError<UniversalXrplError>>),
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum RpcMethod {
    Submit,
    AccountInfo,
    Tx,
    Ledger,
}

#[derive(Debug, Serialize)]
struct LedgerRequestParams {
    ledger_index: LedgerIndex,
}

#[derive(Debug, Serialize)]
struct SubmitRequestParams<'a> {
    #[serde(serialize_with = "serialize_byte_slice_as_upper_hex")]
    tx_blob: &'a [u8],
}

#[derive(Debug, Serialize)]
struct AccountInfoRequestParams {
    account: Address,
    ledger_index: LedgerIndex,
}

#[derive(Debug, Serialize)]
struct TxRequestParams {
    transaction: Hash,
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
        ledger_index: LedgerIndex,
    ) -> Result<AccountInfoResult, HttpRpcClientError> {
        self.send_rpc_request::<_, AccountInfoResult>(
            RpcMethod::AccountInfo,
            &AccountInfoRequestParams {
                account,
                ledger_index,
            },
        )
        .await
    }

    pub async fn tx(&self, transaction: Hash) -> Result<TxResult, HttpRpcClientError> {
        self.send_rpc_request::<_, TxResult>(RpcMethod::Tx, &TxRequestParams { transaction })
            .await
    }

    pub async fn ledger(
        &self,
        ledger_index: LedgerIndex,
    ) -> Result<LedgerResult, HttpRpcClientError> {
        self.send_rpc_request::<_, LedgerResult>(
            RpcMethod::Ledger,
            &LedgerRequestParams { ledger_index },
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

        match body {
            RpcResponse::Success(body) => Ok(body.result),
            RpcResponse::Error(body) => Err(HttpRpcClientError::UniversalError(body.result.error)),
        }
    }
}

impl std::fmt::Display for UniversalXrplError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "xrp ledger universal error: {:?}", self)
    }
}

fn serialize_byte_slice_as_upper_hex<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(value).to_ascii_uppercase())
}
