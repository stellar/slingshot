#![deny(missing_docs)]
#![allow(non_snake_case)]
//! Schnorr signature implementation.

#[macro_use]
extern crate failure;

mod batch;
mod errors;
mod key;
mod serialization;
mod signature;
mod transcript;

#[cfg(test)]
mod tests;

pub use self::batch::{BatchVerification, BatchVerifier, SingleVerifier};
pub use self::errors::StarsigError;
pub use self::key::VerificationKey;
pub use self::signature::Signature;
pub use self::transcript::TranscriptProtocol;
