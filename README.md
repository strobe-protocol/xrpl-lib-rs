# xrpl-lib-rs

XRP Ledger library in Rust.

## Features

- [x] WebAssembly support
- [x] Base58Check encoding/decoding
- [x] Secp256k1 key support
- [ ] RPC client
  - [x] `submit`
  - [x] `account_info`
  - [x] `tx`
  - [x] `ledger`
  - [x] `account_objects` (hook objects only)
  - [x] `account_lines`
  - [x] `ledger_entry` (hook state only)
- [ ] Supported transaction types
  - [x] `Payment`
  - [x] `SetHook` (create only)
  - [x] `AccountSet`
  - [x] `TrustSet`
  - [x] `Invoke`
