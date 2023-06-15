use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TransactionResult {
    /// The transaction did not achieve its intended purpose, but the transaction cost was
    /// destroyed. This result is only final in a validated ledger.
    ClaimedCostOnly(TransactionResultClaimedCostOnly),
    /// The transaction cannot be applied to the server's current (in-progress)
    /// ledger or any later one. It may have already been applied, or the
    /// condition of the ledger makes it impossible to apply in the future.
    Failure(TransactionResultFailure),
    /// The rippled server had an error due to local conditions, such as high
    /// load. You may get a different response if you resubmit to a different
    /// server or at a different time.
    LocalError(TransactionResultLocalError),
    /// The transaction was not valid, due to improper syntax, conflicting
    /// options, a bad signature, or something else.
    MalformedTransaction(TransactionResultMalformedTransaction),
    /// The transaction could not be applied, but it could apply successfully in
    /// a future ledger.
    Retry(TransactionResultRetry),
    /// (Not an error) The transaction succeeded. This result only final in a
    /// validated ledger.
    Success(TransactionResultSuccess),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionResultClaimedCostOnly {
    // TODO: add variants
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionResultFailure {
    /// The sequence number of the transaction is lower than the current sequence number of the
    /// account sending the transaction.
    #[serde(rename = "tefPAST_SEQ")]
    PastSeq,
    // TODO: add variants
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionResultLocalError {
    // TODO: add variants
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionResultMalformedTransaction {
    // TODO: add variants
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionResultRetry {
    // TODO: add variants
}

#[derive(Debug, Serialize, Deserialize)]
pub enum TransactionResultSuccess {
    /// The transaction was applied and forwarded to other servers. If this appears in a validated
    /// ledger, then the transaction's success is final.
    #[serde(rename = "tesSUCCESS")]
    Success,
}
