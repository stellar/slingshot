use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::{Multikey, VerificationKey};

use crate::errors::VMError;

/// Represents a concrete combination of keys used by the transaction signer.
/// Verifier does not interact with this object, so there are no cached precompressed points.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum KeyWitness {
    /// Represents an unsignable key witness
    Unsignable,

    /// Signable key composed of various other keys
    Signable(SignableKeyWitness),
}

pub struct SignableKeyWitness {
    /// Factor to add to the resulting key
    adjustment_factor: Scalar,

    /// The config
    multikey: Multikey,
}
