#![deny(missing_docs)]
#![allow(non_snake_case)]
//! MuSig implementation

#[macro_use]
extern crate failure;

mod counterparty;
mod key;
mod signature;
mod signer;

mod errors;
mod transcript;