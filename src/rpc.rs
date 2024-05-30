use std::str::FromStr;

use reqwest::Client as HttpClient;
use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize};
use url::Url;

use crate::{
    address::Address, amount::TokenValue, currency_code::CurrencyCode, hash::Hash,
    interop::universal_sleep, transaction_result::TransactionResult,
};

const RATE_LIMIT_RETRY_WAIT_DURATION: u32 = 5000;

#[derive(Debug)]
pub struct HttpRpcClient {
    url: Url,
    client: HttpClient,
    max_rate_limit_attempts: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum HttpRpcClientError {
    #[error(transparent)]
    HttpError(reqwest::Error),
    #[error("unsuccessful status code: {0}")]
    UnsuccessfulStatusCode(reqwest::StatusCode),
    #[error(transparent)]
    UniversalError(UniversalXrplError),
    #[error("too many attempts on rate limit")]
    TooManyAttemptsOnRateLimit,
    #[error("json parse error: {0}; actual response: {1}")]
    JsonParseError(serde_json::Error, String),
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
    /// The account's current XRP balance in drops
    #[serde(deserialize_with = "deserialize_string_as_number")]
    pub balance: u64,
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
#[serde(rename_all = "PascalCase")]
pub struct HookExecution {
    pub hook_hash: Hash,
    /// The account that owns the hook
    pub hook_account: Address,
    /// Success if greater than or equal to 0, failure if less than 0.
    #[serde(deserialize_with = "deserialize_hex_string_as_i64")]
    pub hook_return_code: i64,
    /// The string returned by the hook.
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub hook_return_string: Vec<u8>,
    pub hook_emit_count: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HookExecutionHolder {
    pub hook_execution: HookExecution,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Meta {
    pub hook_executions: Option<Vec<HookExecutionHolder>>,
}

#[derive(Debug)]
pub enum Validation {
    NotValidated,
    Validated(Meta),
}

#[derive(Debug)]
pub struct TxSuccess {
    pub account: Address,
    pub hash: Hash,
    /// Transaction metadata is a section of data that gets added to a transaction after it is
    /// processed. Any transaction that gets included in a ledger has metadata, regardless of
    /// whether it is successful. The transaction metadata describes the outcome of the transaction
    /// in detail.
    ///
    /// Transaction metadata always exists when a transaction is validated and it does not when a
    /// transaction is not validated. For example, a payment transaction that is not validated
    /// yet does not have metadata, but will have metadata as soon as it is validated.
    pub validation: Validation,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum TxResult {
    Success(TxSuccess),
    Error(RpcError<TxError>),
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct HookAccountObject {
    pub hook_hash: Hash,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct HookAccountObjectHolder {
    pub hook: HookAccountObject,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
pub enum AccountObjectLedgerEntryType {
    Hook,
    Check,
    DepositPreauth,
    Escrow,
    NftOffer,
    NftPage,
    Offer,
    PaymentChannel,
    SignerList,
    State,
    Ticket,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AccountObject {
    pub hooks: Option<Vec<HookAccountObjectHolder>>,
    pub ledger_entry_type: AccountObjectLedgerEntryType,
}

#[derive(Debug, Deserialize)]
pub struct AccountObjectsSuccess {
    pub account_objects: Vec<AccountObject>,
    #[serde(default = "bool::default")]
    pub validated: bool,
}

#[derive(Debug, Deserialize, Clone)]
pub enum AccountObjectsError {
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
#[serde(untagged)]
pub enum AccountObjectsResult {
    Success(AccountObjectsSuccess),
    Error(RpcError<AccountObjectsError>),
}

#[derive(Debug, Deserialize, Clone)]
pub enum AccountLinesError {
    /// The address specified in the account field of the request does not correspond to an account
    /// in the ledger.
    #[serde(rename = "actNotFound")]
    ActNotFound,
    /// The ledger specified by the ledger_hash or ledger_index does not exist, or it does exist
    /// but the server does not have it.
    #[serde(rename = "lgrNotFound")]
    LgrNotFound,
    /// If the marker field provided is not acceptable.
    #[serde(rename = "lgrNotFound")]
    ActMalformed,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AccountLine {
    /// The unique Address of the counterparty to this trust line.
    pub account: Address,
    /// Representation of the numeric balance currently held against this line. A positive balance
    /// means that the perspective account holds value; a negative balance means that the
    /// perspective account owes value.
    pub balance: TokenValue,
    /// Currency Code identifying what currency this trust line can hold.
    pub currency: CurrencyCode,
    /// The maximum amount of the given currency that this account is willing to owe the peer
    /// account
    pub limit: TokenValue,
    /// The maximum amount of currency that the counterparty account is willing to owe the
    /// perspective account
    pub limit_peer: TokenValue,
}

#[derive(Debug, Deserialize)]
pub struct AccountLinesSuccess {
    pub account: Address,
    pub lines: Vec<AccountLine>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum AccountLinesResult {
    Success(AccountLinesSuccess),
    Error(RpcError<AccountLinesError>),
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub enum LedgerEntryError {
    /// The request specified a removed field, such as generator.
    #[serde(rename = "deprecatedFeature")]
    DeprecatedFeature,
    /// The requested ledger object does not exist in the ledger.
    #[serde(rename = "entryNotFound")]
    EntryNotFound,
    /// The ledger specified by the ledger_hash or ledger_index does not exist, or it does exist
    /// but the server does not have it.
    #[serde(rename = "lgrNotFound")]
    LgrNotFound,
    /// The request improperly specified an Address field.
    #[serde(rename = "malformedAddress")]
    MalformedAddress,
    /// The request improperly specified a Currency Code field.
    #[serde(rename = "malformedCurrency")]
    MalformedCurrency,
    /// The request improperly specified the escrow.owner sub-field.
    #[serde(rename = "malformedOwner")]
    MalformedOwner,
    /// The request provided an invalid combination of fields, or provided the wrong type for one
    /// or more fields.
    #[serde(rename = "malformedRequest")]
    MalformedRequest,
    /// The fields provided in the request did not match any of the expected request formats.
    #[serde(rename = "unknownOption")]
    UnknownOption,
}

// TODO: Implement other ledger entry types
#[derive(Debug, Deserialize)]
#[serde(tag = "LedgerEntryType")]
pub enum LedgerEntryNode {
    #[serde(rename = "HookState")]
    HookState(LedgerEntryHookState),
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct LedgerEntryHookState {
    /// 32 bytes long hex string representing the key used to reference the hook data.
    /// Padded with zeros from the left if the key is shorter than 32 bytes.
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub hook_state_key: Vec<u8>,
    /// Hex string in little endian format. Maximum 128 bytes.
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub hook_state_data: Vec<u8>,
}

#[derive(Debug, Deserialize)]
pub struct LedgerEntrySuccess {
    /// The unique ID of this ledger object.
    #[serde(deserialize_with = "hex::serde::deserialize")]
    pub index: Vec<u8>,
    // The ledger index of the ledger that was used when retrieving this data.
    pub ledger_current_index: u64,
    // Object containing the data of this ledger object, according to the ledger format.
    pub node: LedgerEntryNode,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum LedgerEntryResult {
    Success(LedgerEntrySuccess),
    Error(RpcError<LedgerEntryError>),
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

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "snake_case")]
enum RpcMethod {
    Submit,
    AccountInfo,
    Tx,
    Ledger,
    AccountObjects,
    AccountLines,
    LedgerEntry,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountObjectLedgerEntryTypeRequestParam {
    Hook,
    Check,
    DepositPreauth,
    Escrow,
    NftOffer,
    NftPage,
    Offer,
    PaymentChannel,
    SignerList,
    State,
    Ticket,
}

#[derive(Debug, Serialize)]
struct AccountObjectsRequestParams {
    account: Address,
    ledger_index: LedgerIndex,
    r#type: Option<AccountObjectLedgerEntryTypeRequestParam>,
}

#[derive(Debug, Serialize)]
struct AccountLinesRequestParams {
    account: Address,
    ledger_index: LedgerIndex,
    peer: Option<Address>,
}

#[derive(Debug, Serialize)]
pub struct LedgerEntryHookStateRequestParam {
    pub account: Address,
    #[serde(serialize_with = "hex::serde::serialize_upper")]
    pub key: Vec<u8>,
    #[serde(serialize_with = "hex::serde::serialize_upper")]
    pub namespace_id: Vec<u8>,
}

#[derive(Debug, Serialize)]
struct LedgerEntryRequestParams {
    pub hook_state: LedgerEntryHookStateRequestParam,
}

impl HttpRpcClient {
    pub fn new(url: Url, max_rate_limit_attempts: u32) -> Self {
        Self::new_with_client(url, HttpClient::new(), max_rate_limit_attempts)
    }

    pub fn new_with_client(url: Url, client: HttpClient, max_rate_limit_attempts: u32) -> Self {
        Self {
            url,
            client,
            max_rate_limit_attempts,
        }
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

    pub async fn account_objects(
        &self,
        account: Address,
        ledger_index: LedgerIndex,
        r#type: Option<AccountObjectLedgerEntryTypeRequestParam>,
    ) -> Result<AccountObjectsResult, HttpRpcClientError> {
        self.send_rpc_request::<_, AccountObjectsResult>(
            RpcMethod::AccountObjects,
            &AccountObjectsRequestParams {
                account,
                ledger_index,
                r#type,
            },
        )
        .await
    }

    pub async fn account_lines(
        &self,
        account: Address,
        ledger_index: LedgerIndex,
        peer: Option<Address>,
    ) -> Result<AccountLinesResult, HttpRpcClientError> {
        self.send_rpc_request::<_, AccountLinesResult>(
            RpcMethod::AccountLines,
            &AccountLinesRequestParams {
                account,
                ledger_index,
                peer,
            },
        )
        .await
    }

    // TODO: implement other ledger entry types
    pub async fn ledger_entry(
        &self,
        hook_state: LedgerEntryHookStateRequestParam,
    ) -> Result<LedgerEntryResult, HttpRpcClientError> {
        self.send_rpc_request::<_, LedgerEntryResult>(
            RpcMethod::LedgerEntry,
            &LedgerEntryRequestParams { hook_state },
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
        let mut attempts = self.max_rate_limit_attempts + 1;

        while attempts > 0 {
            let request = self.client.post(self.url.clone()).json(&RpcRequest {
                method: method.clone(),
                params: [request],
            });

            let response = request
                .send()
                .await
                .map_err(HttpRpcClientError::HttpError)?;

            let status_code = response.status();

            // Rippled server will return 503 instead of 429 (too many requests) if it is rate
            // limited
            if status_code == reqwest::StatusCode::SERVICE_UNAVAILABLE {
                attempts -= 1;

                universal_sleep(RATE_LIMIT_RETRY_WAIT_DURATION).await;

                continue;
            }

            if !status_code.is_success() {
                return Err(HttpRpcClientError::UnsuccessfulStatusCode(status_code));
            }

            // This is to ensure that we can see helpful messages in case of an error
            let response_text = response
                .text()
                .await
                .map_err(HttpRpcClientError::HttpError)?;

            let json: RpcResponse<RES> = serde_json::from_str(&response_text)
                .map_err(|e| HttpRpcClientError::JsonParseError(e, response_text))?;

            return match json {
                RpcResponse::Success(body) => Ok(body.result),
                RpcResponse::Error(body) => {
                    Err(HttpRpcClientError::UniversalError(body.result.error))
                }
            };
        }

        Err(HttpRpcClientError::TooManyAttemptsOnRateLimit)
    }
}

impl std::fmt::Display for UniversalXrplError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "xrp ledger universal error: {:?}", self)
    }
}

impl<'de> Deserialize<'de> for TxSuccess {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawTxSuccess {
            #[serde(rename = "Account")]
            account: Address,
            hash: Hash,
            #[serde(default)]
            validated: bool,
            meta: Option<Meta>,
        }

        let raw = RawTxSuccess::deserialize(deserializer)?;

        let validation = match (raw.validated, raw.meta) {
            (true, Some(meta)) => Validation::Validated(meta),
            (false, None) => Validation::NotValidated,
            (true, None) | (false, Some(_)) => {
                return Err(serde::de::Error::custom(
                    "inconsistent `validated` and `meta` fields",
                ));
            }
        };

        Ok(Self {
            account: raw.account,
            hash: raw.hash,
            validation,
        })
    }
}

fn serialize_byte_slice_as_upper_hex<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&hex::encode(value).to_ascii_uppercase())
}

fn deserialize_string_as_number<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: FromStr,
    <T as FromStr>::Err: std::fmt::Display,
{
    let s = String::deserialize(deserializer)?;
    s.parse::<T>().map_err(serde::de::Error::custom)
}

fn deserialize_hex_string_as_i64<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: Deserializer<'de>,
{
    const SIGN_BIT_MASK: u64 = 0x8000000000000000;

    let s = String::deserialize(deserializer)?;
    let maybe_signed_number = u64::from_str_radix(s.as_str(), 16)
        .map_err(|_| serde::de::Error::custom("invalid hexadecimal number"))?;

    let is_negative = maybe_signed_number & SIGN_BIT_MASK != 0;
    if is_negative {
        Ok(-((maybe_signed_number ^ SIGN_BIT_MASK) as i64))
    } else {
        Ok(maybe_signed_number as i64)
    }
}
