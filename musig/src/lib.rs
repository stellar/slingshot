#![deny(missing_docs)]
#![allow(non_snake_case)]
//! Musig implementation

#[macro_use]
extern crate failure;

mod context;
mod counterparty;
mod deferred_verification;
mod key;
mod signature;
mod signer;

mod errors;
mod transcript;

pub use self::deferred_verification::DeferredVerification;
pub use self::key::{Multikey, VerificationKey};
pub use self::signature::Signature;
pub use self::signer::{Party, PartyAwaitingShares};
