#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum AccountSetAsfFlags {
    RequireDest = 1,
    RequireAuth = 2,
    DisallowXRP = 3,
    DisableMaster = 4,
    AccountTxnID = 5,
    NoFreeze = 6,
    GlobalFreeze = 7,
    DefaultRipple = 8,
    DepositAuth = 9,
    AuthorizedNFTokenMinter = 10,
    DisallowIncomingNFTokenOffer = 12,
    DisallowIncomingCheck = 13,
    DisallowIncomingPayChan = 14,
    DisallowIncomingTrustline = 15,
}

#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum AccountSetTfFlags {
    RequireDestTag = 0x00010000,
    OptionalDestTag = 0x00020000,
    RequireAuth = 0x00040000,
    OptionalAuth = 0x00080000,
    DisallowXRP = 0x00100000,
    AllowXRP = 0x00200000,
}

impl From<AccountSetAsfFlags> for u32 {
    fn from(value: AccountSetAsfFlags) -> Self {
        value as Self
    }
}

impl From<AccountSetTfFlags> for u32 {
    fn from(value: AccountSetTfFlags) -> Self {
        value as Self
    }
}
