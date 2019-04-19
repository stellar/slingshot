//! Implementation of Schnorr signature key aggregation.

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::VerificationKey;

use crate::errors::VMError;
use crate::transcript::TranscriptProtocol;

/// Creates an aggregated Schnorr private key for signing from
/// a single party's set of private keys.
/// Mirrors the MuSig multi-party aggregation scheme so that
/// aggregated pubkeys are consistent across both methods.
pub fn aggregated_privkey(privkeys: &[Scalar]) -> Result<Scalar, VMError> {
    match privkeys.len() {
        0 => {
            return Err(VMError::BadArguments);
        }
        1 => {
            return Ok(privkeys[0]);
        }
        _ => {}
    }

    // Initialize transcript to match Musig aggregation scheme.
    let mut transcript = Transcript::new(b"Musig.aggregated-key");
    // Derive public keys from privkeys
    let pubkeys = privkeys
        .iter()
        .map(|p| VerificationKey::from_secret(p))
        .collect::<Vec<_>>();

    // Commit pubkeys
    let n = pubkeys.len();
    transcript.commit_u64(b"n", n as u64);
    for p in pubkeys.iter() {
        transcript.commit_point(b"X", p.as_compressed());
    }

    // Generate aggregated private key
    Ok(privkeys
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut transcript = transcript.clone();
            transcript.commit_u64(b"i", i as u64);
            let x = transcript.challenge_scalar(b"a_i");
            p * x
        })
        .sum())
}
