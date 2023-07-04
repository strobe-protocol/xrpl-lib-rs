use tokio::time::{sleep, Duration};

use crate::{
    hash::Hash,
    rpc::{HttpRpcClient, HttpRpcClientError, TxError, TxResult, TxSuccess, Validation},
};

// Approximate time for a ledger to close, in milliseconds
const LEDGER_CLOSE_DURATION_MS: u64 = 3000;
// Automated processes should use a value of 4 greater than the last validated ledger index to make
// sure that a transaction is validated or rejected in a predictable and prompt way.
const LAST_VALIDATED_LEDGER_OFFSET: u32 = 4;

#[derive(Debug)]
pub enum WaitForTransactionError {
    Timeout,
    TxError(TxError),
    HttpRpcClientError(HttpRpcClientError),
}

pub async fn wait_for_transaction(
    transaction_hash: Hash,
    rpc: &HttpRpcClient,
) -> Result<TxSuccess, WaitForTransactionError> {
    let mut attempts = 0;

    loop {
        if attempts >= 20 {
            return Err(WaitForTransactionError::Timeout);
        }

        let tx = rpc
            .tx(transaction_hash)
            .await
            .map_err(WaitForTransactionError::HttpRpcClientError)?;

        match tx {
            TxResult::Success(success) => {
                if let Validation::Validated(_) = success.validation {
                    return Ok(success);
                }
            }
            TxResult::Error(error) => {
                return Err(WaitForTransactionError::TxError(error.error));
            }
        }

        sleep(Duration::from_millis(LEDGER_CLOSE_DURATION_MS)).await;
        attempts += 1;
    }
}

pub fn create_last_ledger_sequence(last_validated_ledger_index: u32) -> u32 {
    last_validated_ledger_index + LAST_VALIDATED_LEDGER_OFFSET
}
