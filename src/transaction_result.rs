use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionResultClaimedCostOnly {
    /// The transaction tried to accept an offer that was placed by the same account to buy or
    /// sell a non-fungible token. (Added by the NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tecCANT_ACCEPT_OWN_NFTOKEN_OFFER")]
    CantAcceptOwnNftokenOffer,
    /// Unspecified failure, with transaction cost destroyed.
    #[serde(rename = "tecCLAIM")]
    Claim,
    /// This EscrowCreate or EscrowFinish transaction contained a malformed or mismatched
    /// crypto-condition.
    #[serde(rename = "tecCRYPTOCONDITION_ERROR")]
    CryptoconditionError,
    /// The transaction tried to add an object (such as a trust line, Check, Escrow, or Payment
    /// Channel) to an account's owner directory, but that account cannot own any more objects in
    /// the ledger.
    #[serde(rename = "tecDIR_FULL")]
    DirFull,
    /// The transaction tried to create an object (such as a DepositPreauth authorization) that
    /// already exists.
    #[serde(rename = "tecDUPLICATE")]
    Duplicate,
    /// The Payment transaction omitted a destination tag, but the destination account has the
    /// lsfRequireDestTag flag enabled. New in: rippled 0.28.0
    #[serde(rename = "tecDST_TAG_NEEDED")]
    DstTagNeeded,
    /// The transaction tried to create an object (such as an Offer or a Check) whose provided
    /// Expiration time has already passed.
    #[serde(rename = "tecEXPIRED")]
    Expired,
    /// An unspecified error occurred when processing the transaction.
    #[serde(rename = "tecFAILED_PROCESSING")]
    FailedProcessing,
    /// The OfferCreate transaction failed because one or both of the assets involved are subject
    /// to a global freeze.
    #[serde(rename = "tecFROZEN")]
    Frozen,
    /// The AccountDelete transaction failed because the account to be deleted owns objects that
    /// cannot be deleted. See Deletion of Accounts for details.
    #[serde(rename = "tecHAS_OBLIGATIONS")]
    HasObligations,
    /// The transaction failed because the sending account does not have enough XRP to create a new
    /// trust line. (See: Reserves) This error occurs when the counterparty already has a trust
    /// line in a non-default state to the sending account for the same currency. (See
    /// tecNO_LINE_INSUF_RESERVE for the other case.)
    #[serde(rename = "tecINSUF_RESERVE_LINE")]
    InsufReserveLine,
    /// The transaction failed because the sending account does not have enough XRP to create a new
    /// Offer. (See: Reserves)
    #[serde(rename = "tecINSUF_RESERVE_OFFER")]
    InsufReserveOffer,
    /// The transaction failed because the sending account does not have enough XRP to pay the
    /// transaction cost that it specified. (In this case, the transaction processing destroys all
    /// of the sender's XRP even though that amount is lower than the specified transaction cost.)
    /// This result only occurs if the account's balance decreases after this transaction has been
    /// distributed to enough of the network to be included in a consensus set. Otherwise, the
    /// transaction fails with terINSUF_FEE_B before being distributed.
    #[serde(rename = "tecINSUFF_FEE")]
    InsuffFee,
    /// One of the accounts involved does not hold enough of a necessary asset. (Added by the
    /// NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tecINSUFFICIENT_FUNDS")]
    InsufficientFunds,
    /// The amount specified is not enough to pay all fees involved in the transaction. For
    /// example, when trading a non-fungible token, the buy amount may not be enough to pay both
    /// the broker fee and the sell amount. (Added by the NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tecINSUFFICIENT_PAYMENT")]
    InsufficientPayment,
    /// The transaction would increase the reserve requirement higher than the sending account's
    /// balance. SignerListSet, PaymentChannelCreate, PaymentChannelFund, and EscrowCreate can
    /// return this error code. See Signer Lists and Reserves for more information.
    #[serde(rename = "tecINSUFFICIENT_RESERVE")]
    InsufficientReserve,
    /// Unspecified internal error, with transaction cost applied. This error code should not
    /// normally be returned. If you can reproduce this error, please report an issue .
    #[serde(rename = "tecINTERNAL")]
    Internal,
    /// An invariant check failed when trying to execute this transaction. Added by the
    /// EnforceInvariants amendment. If you can reproduce this error, please report an issue .
    #[serde(rename = "tecINVARIANT_FAILED")]
    InvariantFailed,
    /// The OfferCreate transaction specified the tfFillOrKill flag and could not be filled, so it
    /// was killed. (Added by the fix1578 amendment.)
    #[serde(rename = "tecKILLED")]
    Killed,
    /// A sequence number field is already at its maximum. This includes the MintedNFTokens field.
    /// (Added by the NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tecMAX_SEQUENCE_REACHED")]
    MaxSequenceReached,
    /// This transaction tried to cause changes that require the master key, such as disabling the
    /// master key or giving up the ability to freeze balances. New in: rippled 0.28.0
    #[serde(rename = "tecNEED_MASTER_KEY")]
    NeedMasterKey,
    /// The NFTokenAcceptOffer transaction attempted to match incompatible offers to buy and sell a
    /// non-fungible token. (Added by the NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tecNFTOKEN_BUY_SELL_MISMATCH")]
    NftokenBuySellMismatch,
    /// One or more of the offers specified in the transaction was not the right type of offer.
    /// (For example, a buy offer was specified in the NFTokenSellOffer field.) (Added by the
    /// NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tecNFTOKEN_OFFER_TYPE_MISMATCH")]
    NftokenOfferTypeMismatch,
    /// The transaction tried to remove the only available method of authorizing transactions. This
    /// could be a SetRegularKey transaction to remove the regular key, a SignerListSet transaction
    /// to delete a SignerList, or an AccountSet transaction to disable the master key. (Prior to
    /// rippled 0.30.0, this was called tecMASTER_DISABLED.)
    #[serde(rename = "tecNO_ALTERNATIVE_KEY")]
    NoAlternativeKey,
    /// The transaction failed because it needs to add a balance on a trust line to an account with
    /// the lsfRequireAuth flag enabled, and that trust line has not been authorized. If the trust
    /// line does not exist at all, tecNO_LINE occurs instead.
    #[serde(rename = "tecNO_AUTH")]
    NoAuth,
    /// The account on the receiving end of the transaction does not exist. This includes Payment
    /// and TrustSet transaction types. (It could be created if it received enough XRP.)
    #[serde(rename = "tecNO_DST")]
    NoDst,
    /// The account on the receiving end of the transaction does not exist, and the transaction is
    /// not sending enough XRP to create it.
    #[serde(rename = "tecNO_DST_INSUF_XRP")]
    NoDstInsufXrp,
    /// The transaction tried to modify a ledger object, such as a Check, Payment Channel, or
    /// Deposit Preauthorization, but the specified object does not exist. It may have already been
    /// deleted by a previous transaction or the transaction may have an incorrect value in an ID
    /// field such as CheckID, Channel, Unauthorize.
    #[serde(rename = "tecNO_ENTRY")]
    NoEntry,
    /// The account specified in the issuer field of a currency amount does not exist.
    #[serde(rename = "tecNO_ISSUER")]
    NoIssuer,
    /// The TakerPays field of the OfferCreate transaction specifies an asset whose issuer has
    /// lsfRequireAuth enabled, and the account making the offer does not have a trust line for
    /// that asset. (Normally, making an offer implicitly creates a trust line if necessary, but in
    /// this case it does not bother because you cannot hold the asset without authorization.) If
    /// the trust line exists, but is not authorized, tecNO_AUTH occurs instead.
    #[serde(rename = "tecNO_LINE")]
    NoLine,
    /// The transaction failed because the sending account does not have enough XRP to create a new
    /// trust line. (See: Reserves) This error occurs when the counterparty does not have a trust
    /// line to this account for the same currency. (See tecINSUF_RESERVE_LINE for the other case.)
    #[serde(rename = "tecNO_LINE_INSUF_RESERVE")]
    NoLineInsufReserve,
    /// The transaction failed because it tried to set a trust line to its default state, but the
    /// trust line did not exist.
    #[serde(rename = "tecNO_LINE_REDUNDANT")]
    NoLineRedundant,
    /// The sender does not have permission to do this operation. For example, the EscrowFinish
    /// transaction tried to release a held payment before its FinishAfter time, someone tried to
    /// use PaymentChannelFund on a channel the sender does not own, or a Payment tried to deliver
    /// funds to an account with the "DepositAuth" flag enabled.
    #[serde(rename = "tecNO_PERMISSION")]
    NoPermission,
    /// The AccountSet transaction tried to disable the master key, but the account does not have
    /// another way to authorize transactions. If multi-signing is enabled, this code is deprecated
    /// and tecNO_ALTERNATIVE_KEY is used instead.
    #[serde(rename = "tecNO_REGULAR_KEY")]
    NoRegularKey,
    /// The transaction tried to mint or acquire a non-fungible token but the account receiving the
    /// NFToken does not have a directory page that can hold it. This situation is rare. (Added by
    /// the NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tecNO_SUITABLE_NFTOKEN_PAGE")]
    NoSuitableNftokenPage,
    /// The transaction referenced an Escrow or PayChannel ledger object that doesn't exist, either
    /// because it never existed or it has already been deleted. (For example, another EscrowFinish
    /// transaction has already executed the held payment.) Alternatively, the destination account
    /// has asfDisallowXRP set so it cannot be the destination of this PaymentChannelCreate or
    /// EscrowCreate transaction.
    #[serde(rename = "tecNO_TARGET")]
    NoTarget,
    /// One of the objects specified by this transaction did not exist in the ledger. (Added by the
    /// NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tecOBJECT_NOT_FOUND")]
    ObjectNotFound,
    /// This transaction could not be processed, because the server created an excessively large
    /// amount of metadata when it tried to apply the transaction. New in: rippled 0.29.0-hf1
    #[serde(rename = "tecOVERSIZE")]
    Oversize,
    /// The transaction cannot succeed because the sender already owns objects in the ledger. For
    /// example, an account cannot enable the lsfRequireAuth flag if it has any trust lines or
    /// available offers.
    #[serde(rename = "tecOWNERS")]
    Owners,
    /// The transaction failed because the provided paths did not have enough liquidity to send
    /// anything at all. This could mean that the source and destination accounts are not linked by
    /// trust lines.
    #[serde(rename = "tecPATH_DRY")]
    PathDry,
    /// The transaction failed because the provided paths did not have enough liquidity to send the
    /// full amount.
    #[serde(rename = "tecPATH_PARTIAL")]
    PathPartial,
    /// The AccountDelete transaction failed because the account to be deleted had a Sequence
    /// number that is too high. The current ledger index must be at least 256 higher than the
    /// account's sequence number.
    #[serde(rename = "tecTOO_SOON")]
    TooSoon,
    /// The transaction failed because the account does not hold enough XRP to pay the amount in
    /// the transaction and satisfy the additional reserve necessary to execute this transaction.
    #[serde(rename = "tecUNFUNDED")]
    Unfunded,
    /// The transaction failed because the sending account is trying to send more XRP than it
    /// holds, not counting the reserve.
    #[serde(rename = "tecUNFUNDED_PAYMENT")]
    UnfundedPayment,
    /// The OfferCreate transaction failed because the account creating the offer does not have any
    /// of the TakerGets currency.
    #[serde(rename = "tecUNFUNDED_OFFER")]
    UnfundedOffer,
    // DEPRECATED.
    // #[serde(rename = "tecUNFUNDED_ADD")]
    // UnfundedAdd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionResultFailure {
    /// The sequence number of the transaction is lower than the current sequence number of the
    /// account sending the transaction.
    #[serde(rename = "tefPAST_SEQ")]
    PastSeq,
    /// The same exact transaction has already been applied.
    #[serde(rename = "tefALREADY")]
    Already,
    /// The key used to sign this account is not authorized to modify this account. (It could be
    /// authorized if the account had the same key set as the Regular Key.)
    #[serde(rename = "tefBAD_AUTH")]
    BadAuth,
    /// The single signature provided to authorize this transaction does not match the master key,
    /// but no regular key is associated with this address.
    #[serde(rename = "tefBAD_AUTH_MASTER")]
    BadAuthMaster,
    /// While processing the transaction, the ledger was discovered in an unexpected state. If you
    /// can reproduce this error, please report an issue  to get it fixed.
    #[serde(rename = "tefBAD_LEDGER")]
    BadLedger,
    /// The transaction was multi-signed, but the total weights of all included signatures did not
    /// meet the quorum.
    #[serde(rename = "tefBAD_QUORUM")]
    BadQuorum,
    /// The transaction was multi-signed, but contained a signature for an address
    /// not part of a SignerList associated with the sending account.
    #[serde(rename = "tefBAD_SIGNATURE")]
    BadSignature,
    /// While processing the transaction, the server entered an unexpected state. This may be
    /// caused by unexpected inputs, for example if the binary data for the transaction is grossly
    /// malformed. If you can reproduce this error, please report an issue  to get it fixed.
    #[serde(rename = "tefEXCEPTION")]
    Exception,
    /// Unspecified failure in applying the transaction.
    #[serde(rename = "tefFAILURE")]
    Failure,
    /// When trying to apply the transaction, the server entered an unexpected state. If you can
    /// reproduce this error, please report an issue  to get it fixed.
    #[serde(rename = "tefINTERNAL")]
    Internal,
    /// An invariant check failed when trying to claim the transaction cost. Added by the
    /// EnforceInvariants amendment. If you can reproduce this error, please report an issue .
    #[serde(rename = "tefINVARIANT_FAILED")]
    InvariantFailed,
    /// The transaction was signed with the account's master key, but the account has the
    /// lsfDisableMaster field set.
    #[serde(rename = "tefMASTER_DISABLED")]
    MasterDisabled,
    /// The transaction included a LastLedgerSequence parameter, but the current ledger's sequence
    /// number is already higher than the specified value.
    #[serde(rename = "tefMAX_LEDGER")]
    MaxLedger,
    /// The transaction attempted to send a non-fungible token to another account, but the NFToken
    /// has the lsfTransferable flag disabled and the transfer would not be to or from the issuer.
    /// (Added by the NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "tefNFTOKEN_IS_NOT_TRANSFERABLE")]
    NFTokenIsNotTransferable,
    /// The TrustSet transaction tried to mark a trust line as authorized, but the lsfRequireAuth
    /// flag is not enabled for the corresponding account, so authorization is not necessary.
    #[serde(rename = "tefNO_AUTH_REQUIRED")]
    NoAuthRequired,
    /// The transaction attempted to use a Ticket, but the specified TicketSequence number does not
    /// exist in the ledger, and cannot be created in the future because it is earlier than the
    /// sender's current sequence number.
    #[serde(rename = "tefNO_TICKET")]
    NoTicket,
    /// The transaction was multi-signed, but the sending account has no SignerList defined.
    #[serde(rename = "tefNOT_MULTI_SIGNING")]
    NotMultiSigning,
    /// The transaction would affect too many objects in the ledger. For example, this was an
    /// AccountDelete transaction but the account to be deleted owns over 1000 objects in the
    /// ledger.
    #[serde(rename = "tefTOO_BIG")]
    TooBig,
    /// The transaction contained an AccountTxnID field (or the deprecated PreviousTxnID field),
    /// but the transaction specified there does not match the account's previous transaction.
    #[serde(rename = "tefWRONG_PRIOR")]
    WrongPrior,
    // tefBAD_ADD_AUTH	DEPRECATED.
    // tefCREATED	DEPRECATED.
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionResultLocalError {
    /// The transaction specified a domain value (for example, the Domain field of an
    /// AccountSet transaction) that cannot be used, probably because it is too long to store in
    /// the ledger.
    #[serde(rename = "telBAD_DOMAIN")]
    BadDomain,
    /// The transaction contains too many paths for the local server to process.
    #[serde(rename = "telBAD_PATH_COUNT")]
    BadPathCount,
    /// The transaction specified a public key value (for example, as the MessageKey field of an
    /// AccountSet transaction) that cannot be used, probably because it is not the right length.
    #[serde(rename = "telBAD_PUBLIC_KEY")]
    BadPublicKey,
    /// The transaction did not meet the open ledger cost, but this server did not queue this
    /// transaction because it did not meet the queuing restrictions. For example, a transaction
    /// returns this code when the sender already has 10 other transactions in the queue. You can
    /// try again later or sign and submit a replacement transaction with a higher transaction cost
    /// in the Fee field.
    #[serde(rename = "telCAN_NOT_QUEUE")]
    CanNotQueue,
    /// The transaction did not meet the open ledger cost and also was not added to the transaction
    /// queue because the sum of potential XRP costs of already-queued transactions is greater than
    /// the expected balance of the account. You can try again later, or try submitting to a
    /// different server.
    #[serde(rename = "telCAN_NOT_QUEUE_BALANCE")]
    CanNotQueueBalance,
    /// The transaction did not meet the open ledger cost and also was not added to the transaction
    /// queue. This transaction could not replace an existing transaction in the queue because it
    /// would block already-queued transactions from the same sender by changing authorization
    /// methods. (This includes all SetRegularKey and SignerListSet transactions, as well as
    /// AccountSet transactions that change the RequireAuth/OptionalAuth, DisableMaster, or
    /// AccountTxnID flags.) You can try again later, or try submitting to a different server.
    #[serde(rename = "telCAN_NOT_QUEUE_BLOCKS")]
    CanNotQueueBlocks,
    /// The transaction did not meet the open ledger cost and also was not added to the transaction
    /// queue because a transaction queued ahead of it from the same sender blocks it. (This
    /// includes all SetRegularKey and SignerListSet transactions, as well as AccountSet
    /// transactions that change the RequireAuth/OptionalAuth, DisableMaster, or AccountTxnID
    /// flags.) You can try again later, or try submitting to a different server.
    #[serde(rename = "telCAN_NOT_QUEUE_BLOCKED")]
    CanNotQueueBlocked,
    /// The transaction did not meet the open ledger cost and also was not added to the transaction
    /// queue. This code occurs when a transaction with the same sender and sequence number already
    /// exists in the queue and the new one does not pay a large enough transaction cost to replace
    /// the existing transaction. To replace a transaction in the queue, the new transaction must
    /// have a Fee value that is at least 25% more, as measured in fee levels. You can increase the
    /// Fee and try again, send this with a higher Sequence number so it doesn't replace an
    /// existing transaction, or try sending to another server.
    #[serde(rename = "telCAN_NOT_QUEUE_FEE")]
    CanNotQueueFee,
    /// The transaction did not meet the open ledger cost and the server did not queue this
    /// transaction because this server's transaction queue is full. You could increase the Fee and
    /// try again, try again later, or try submitting to a different server. The new transaction
    /// must have a higher transaction cost, as measured in fee levels, than the transaction in the
    /// queue with the smallest transaction cost.
    #[serde(rename = "telCAN_NOT_QUEUE_FULL")]
    CanNotQueueFull,
    /// An unspecified error occurred when processing the transaction.
    #[serde(rename = "telFAILED_PROCESSING")]
    FailedProcessing,
    /// The Fee from the transaction is not high enough to meet the server's current transaction
    /// cost requirement, which is derived from its load level and network-level requirements.
    /// If the individual server is too busy to process your transaction right now,
    /// it may cache the transaction and automatically retry later.
    #[serde(rename = "telINSUF_FEE_P")]
    InsufficientFee,
    /// Unspecified local error.
    #[serde(rename = "telLOCAL_ERROR")]
    LocalError,
    /// The transaction is an XRP payment that would fund a new account, but the tfPartialPayment
    /// flag was enabled. This is disallowed.
    #[serde(rename = "telNO_DST_PARTIAL")]
    NoDestinationPartial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionResultMalformedTransaction {
    /// An amount specified by the transaction (for example the destination Amount or SendMax
    /// values of a Payment) was invalid, possibly because it was a negative number.
    #[serde(rename = "temBAD_AMOUNT")]
    BadAmount,
    /// The key used to sign this transaction does not match the master key for the account
    /// sending it, and the account does not have a Regular Key set.
    #[serde(rename = "temBAD_AUTH_MASTER")]
    BadAuthMaster,
    /// The transaction improperly specified a currency field. See Specifying Currency Amounts
    /// for the correct format.
    #[serde(rename = "temBAD_CURRENCY")]
    BadCurrency,
    /// The transaction improperly specified an expiration value, for example as part of an
    /// OfferCreate transaction. Alternatively, the transaction did not specify a required
    /// expiration value, for example as part of an EscrowCreate transaction.
    #[serde(rename = "temBAD_EXPIRATION")]
    BadExpiration,
    /// The transaction improperly specified its Fee value, for example by listing a
    /// non-XRP currency or some negative amount of XRP.
    #[serde(rename = "temBAD_FEE")]
    BadFee,
    /// The transaction improperly specified the issuer field of some currency included in the
    /// request.
    #[serde(rename = "temBAD_ISSUER")]
    BadIssuer,
    /// The TrustSet transaction improperly specified the LimitAmount value of a trust line.
    #[serde(rename = "temBAD_LIMIT")]
    BadLimit,
    /// The NFTokenMint transaction improperly specified the TransferFee field of the
    /// transaction. (Added by the NonFungibleTokensV1_1 amendment.)
    #[serde(rename = "temBAD_NFTOKEN_TRANSFER_FEE")]
    BadNftTokenTransferFee,
    /// The OfferCreate transaction specifies an invalid offer, such as offering
    /// to trade XRP for itself, or offering a negative amount.
    #[serde(rename = "temBAD_OFFER")]
    BadOffer,
    /// The Payment transaction specifies one or more Paths improperly, for example
    /// including an issuer for XRP, or specifying an account differently.
    #[serde(rename = "temBAD_PATH")]
    BadPath,
    /// One of the Paths in the Payment transaction was flagged as a loop, so it
    /// cannot be processed in a bounded amount of time.
    #[serde(rename = "temBAD_PATH_LOOP")]
    BadPathLoop,
    /// The Payment transaction used the tfLimitQuality flag in a direct XRP-to-XRP payment,
    /// even though XRP-to-XRP payments do not involve any conversions.
    #[serde(rename = "temBAD_SEND_XRP_LIMIT")]
    BadSendXrpLimit,
    /// The Payment transaction included a SendMax field in a direct XRP-to-XRP payment,
    /// even though sending XRP should never require SendMax. (XRP is only valid in SendMax
    /// if the destination Amount is not XRP.)
    #[serde(rename = "temBAD_SEND_XRP_MAX")]
    BadSendXrpMax,
    /// The Payment transaction used the tfNoDirectRipple flag for a direct XRP-to-XRP
    /// payment, even though XRP-to-XRP payments are always direct.
    #[serde(rename = "temBAD_SEND_XRP_NO_DIRECT")]
    BadSendXrpNoDirect,
    /// The Payment transaction used the tfPartialPayment flag for a direct XRP-to-XRP payment,
    /// even though XRP-to-XRP payments should always deliver the full amount.
    #[serde(rename = "temBAD_SEND_XRP_PARTIAL")]
    BadSendXrpPartial,
    /// The Payment transaction included Paths while sending XRP, even though XRP-to-XRP
    /// payments should always be direct.
    #[serde(rename = "temBAD_SEND_XRP_PATHS")]
    BadSendXrpPaths,
    /// The transaction is references a sequence number that is higher than its own
    /// Sequence number, for example trying to cancel an offer that would have to
    /// be placed after the transaction that cancels it.
    #[serde(rename = "temBAD_SEQUENCE")]
    BadSequence,
    /// The signature to authorize this transaction is either missing, or formed in a way that is
    /// not a properly-formed signature. (See tecNO_PERMISSION for the case where the signature
    /// is properly formed, but not authorized for this account.)
    #[serde(rename = "temBAD_SIGNATURE")]
    BadSignature,
    /// The Account on whose behalf this transaction is being sent (the "source account")
    /// is not a properly-formed account address.
    #[serde(rename = "temBAD_SRC_ACCOUNT")]
    BadSrcAccount,
    /// The TransferRate field of an AccountSet transaction is not properly formatted or
    /// out of the acceptable range.
    #[serde(rename = "temBAD_TRANSFER_RATE")]
    BadTransferRate,
    /// The sender of the DepositPreauth transaction was also specified as the account to
    /// preauthorize. You cannot preauthorize yourself.
    #[serde(rename = "temCANNOT_PREAUTH_SELF")]
    CannotPreauthSelf,
    /// The transaction improperly specified a destination address as the Account sending
    /// the transaction. This includes trust lines (where the destination address is the issuer
    /// field of LimitAmount) and payment channels (where the destination address is the
    /// Destination field).
    #[serde(rename = "temDST_IS_SRC")]
    DstIsSrc,
    /// The transaction improperly omitted a destination. This could be the Destination field of a
    /// Payment transaction, or the issuer sub-field of the LimitAmount field fo a TrustSet
    /// transaction.
    #[serde(rename = "temDST_NEEDED")]
    DstNeeded,
    /// The transaction is otherwise invalid. For example, the transaction ID may not be the right
    /// format, the signature may not be formed properly, or something else went wrong in
    /// understanding the transaction.
    #[serde(rename = "temINVALID")]
    Invalid,
    /// The transaction includes a TicketCount field, but the number of Tickets specified is
    /// invalid.
    #[serde(rename = "temINVALID_ACCOUNT")]
    InvalidAccount,
    /// The transaction includes a Flag that does not exist, or includes a contradictory
    /// combination of flags.
    #[serde(rename = "temINVALID_FLAG")]
    InvalidFlag,
    /// Unspecified problem with the format of the transaction.
    #[serde(rename = "temMALFORMED")]
    Malformed,
    /// The transaction would do nothing; for example, it is sending a payment directly to the
    /// sending account, or creating an offer to buy and sell the same currency from the same
    /// issuer.
    #[serde(rename = "temREDUNDANT")]
    Redundant,
    /// The Payment transaction includes an empty Paths field, but paths are necessary to complete
    /// this payment.
    #[serde(rename = "temRIPPLE_EMPTY")]
    RippleEmpty,
    /// The SignerListSet transaction includes a SignerWeight that is invalid, for example a zero
    /// or negative value.
    #[serde(rename = "temBAD_WEIGHT")]
    BadWeight,
    /// The SignerListSet transaction includes a signer who is invalid. For example, there may be
    /// duplicate entries,  or the owner of the SignerList may also be a member.
    #[serde(rename = "temBAD_SIGNER")]
    BadSigner,
    /// The SignerListSet transaction has an invalid SignerQuorum value. Either the value is not
    /// greater than zero, or it is more than the sum of all signers in the list.
    #[serde(rename = "temBAD_QUORUM")]
    BadQuorum,
    /// Used internally only. This code should never be returned.
    #[serde(rename = "temUNCERTAIN")]
    Uncertain,
    /// Used internally only. This code should never be returned.
    #[serde(rename = "temUNKNOWN")]
    Unknown,
    /// The transaction requires logic that is disabled. Typically this means you are trying to use
    /// an amendment that is not enabled for the current ledger.
    #[serde(rename = "temDISABLED")]
    Disabled,
    // temREDUNDANT_SEND_MAX	Removed in: rippled 0.28.0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionResultRetry {
    /// The account sending the transaction does not have enough XRP to pay the Fee specified in
    /// the transaction.
    #[serde(rename = "terINSUF_FEE_B")]
    InsurFeeB,
    /// The account sending the transaction does not have enough XRP to pay the Fee specified in
    /// the transaction.
    #[serde(rename = "terLAST")]
    Last,
    /// The address sending the transaction is not funded in the ledger (yet).
    #[serde(rename = "terNO_ACCOUNT")]
    NoAccount,
    /// The transaction would involve adding currency issued by an account with lsfRequireAuth
    /// enabled to a trust line that is not authorized. For example, you placed an offer to buy
    /// a currency you aren't authorized to hold.
    #[serde(rename = "terNO_AUTH")]
    NoAuth,
    /// Used internally only. This code should never be returned.
    #[serde(rename = "terNO_LINE")]
    NoLine,
    /// Used internally only. This code should never be returned.
    #[serde(rename = "terNO_RIPPLE")]
    NoRipple,
    /// The transaction requires that account sending it has a nonzero "owners count", so the
    /// transaction cannot succeed. For example, an account cannot enable the lsfRequireAuth
    /// flag if it has any trust lines or available offers.
    #[serde(rename = "terOWNERS")]
    Owners,
    /// The Sequence number of the current transaction is higher than the current sequence number
    /// of the account sending the transaction.
    #[serde(rename = "terPRE_SEQ")]
    PreSeq,
    /// The transaction attempted to use a Ticket, but the specified TicketSequence number does not
    /// exist in the ledger. However, the Ticket could still be created by another transaction.
    #[serde(rename = "terPRE_TICKET")]
    PreTicket,
    /// Unspecified retriable error.
    #[serde(rename = "terRETRY")]
    Retry,
    /// The transaction met the load-scaled transaction cost but did not meet the open ledger
    /// requirement, so the transaction has been queued for a future ledger.
    #[serde(rename = "terQUEUED")]
    Queued,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransactionResultSuccess {
    /// The transaction was applied and forwarded to other servers. If this appears in a validated
    /// ledger, then the transaction's success is final.
    #[serde(rename = "tesSUCCESS")]
    Success,
}
