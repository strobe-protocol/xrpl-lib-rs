use futures_util::join;

use crate::{
    address::Address,
    hash::Hash,
    interop::universal_sleep,
    rpc::{
        AccountInfoError, AccountInfoResult, HttpRpcClient, HttpRpcClientError, LedgerError,
        LedgerIndex, LedgerIndexShortcut, LedgerResult, TxError, TxResult, TxSuccess, Validation,
    },
};

// Approximate time for a ledger to close, in milliseconds
const LEDGER_CLOSE_DURATION_MS: u32 = 3000;
// Automated processes should use a value of 4 greater than the last validated ledger index to make
// sure that a transaction is validated or rejected in a predictable and prompt way.
const LAST_VALIDATED_LEDGER_OFFSET: u32 = 4;

#[derive(Debug)]
pub enum WaitForTransactionError {
    Timeout,
    TxError(TxError),
    HttpRpcClientError(HttpRpcClientError),
}

#[derive(Debug)]
pub struct TransactionContext {
    /// Sequencer of the ledger after which the transaction must not be included.
    pub last_ledger_sequence: u32,
    /// The next account sequence to use.
    pub account_sequence: u32,
}

#[derive(Debug)]
pub enum GetTransactionContextError {
    RpcError(HttpRpcClientError),
    LedgerError(LedgerError),
    AccountInfoError(AccountInfoError),
}

pub async fn wait_for_transaction(
    transaction_hash: Hash,
    rpc: &HttpRpcClient,
) -> Result<TxSuccess, WaitForTransactionError> {
    let mut attempts = 0;

    loop {
        if attempts >= 5 {
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

        universal_sleep(LEDGER_CLOSE_DURATION_MS).await;
        attempts += 1;
    }
}

pub fn create_last_ledger_sequence(last_validated_ledger_index: u32) -> u32 {
    last_validated_ledger_index + LAST_VALIDATED_LEDGER_OFFSET
}

pub async fn get_transaction_context(
    account_address: Address,
    rpc: &HttpRpcClient,
) -> Result<TransactionContext, GetTransactionContextError> {
    let (account_info_result, last_validated_ledger_result) = join!(
        rpc.account_info(
            account_address,
            LedgerIndex::Shortcut(LedgerIndexShortcut::Current)
        ),
        rpc.ledger(LedgerIndex::Shortcut(LedgerIndexShortcut::Validated))
    );

    let account_info = match account_info_result.map_err(GetTransactionContextError::RpcError)? {
        AccountInfoResult::Success(value) => value,
        AccountInfoResult::Error(err) => {
            return Err(GetTransactionContextError::AccountInfoError(err.error))
        }
    };

    let last_validated_ledger = match last_validated_ledger_result
        .map_err(GetTransactionContextError::RpcError)?
    {
        LedgerResult::Success(value) => value,
        LedgerResult::Error(err) => return Err(GetTransactionContextError::LedgerError(err.error)),
    };

    Ok(TransactionContext {
        last_ledger_sequence: create_last_ledger_sequence(last_validated_ledger.ledger_index),
        account_sequence: account_info.account_data.sequence,
    })
}
