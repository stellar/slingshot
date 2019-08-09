#![deny(missing_docs)]
#![allow(non_snake_case)]
//! Schnorr signature implementation.

#[macro_use]
extern crate failure;

mod deferred_verification;
mod key;
mod signature;
mod errors;
mod transcript;

pub use self::deferred_verification::DeferredVerification;
pub use self::errors::SchnorrError;
pub use self::key::VerificationKey;
pub use self::signature::Signature;
