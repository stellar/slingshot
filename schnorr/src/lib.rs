#![deny(missing_docs)]
#![allow(non_snake_case)]
//! Schnorr signature implementation.

#[macro_use]
extern crate failure;

mod errors;
mod key;
mod signature;
mod transcript;

pub use self::errors::SchnorrError;
pub use self::key::VerificationKey;
pub use self::signature::Signature;
