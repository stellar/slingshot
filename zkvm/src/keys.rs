//! Implementation of Schnorr signature key aggregation.

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::VerificationKey;

use crate::errors::VMError;
use crate::point_ops::PointOp;
use crate::transcript::TranscriptProtocol;

/// Creates an aggregated Schnorr private key for signing from
/// a single party's set of private keys.
pub fn aggregated_privkey(privkeys: &[Scalar]) -> Scalar {
    let mut transcript = Transcript::new(b"ZkVM.key");
    // Derive public keys from privkeys
    let pubkeys = privkeys
        .iter()
        .map(|p| VerificationKey::from_secret(p))
        .collect::<Vec<_>>();

    // Commit pubkeys
    let n = pubkeys.len();
    transcript.commit_u64(b"n", n as u64);
    for p in pubkeys.iter() {
        transcript.commit_point(b"P", &p.0);
    }

    // Generate aggregated private key
    privkeys
        .iter()
        .map(|p| {
            let x = transcript.challenge_scalar(b"x");
            p * x
        })
        .sum()
}

/// Creates an aggregated Schnorr public key for verifying signatures from a
/// single party's set of private keys.
pub fn aggregated_pubkey(pubkeys: &[VerificationKey]) -> Result<VerificationKey, VMError> {
    let mut transcript = Transcript::new(b"ZkVM.key");
    transcript.commit_u64(b"n", pubkeys.len() as u64);
    for p in pubkeys.iter() {
        transcript.commit_point(b"P", &p.0);
    }

    let pairs = pubkeys
        .iter()
        .map(|p| {
            let x = transcript.challenge_scalar(b"x");
            (x, p.0)
        })
        .collect::<Vec<_>>();

    let pubkey_op = PointOp {
        primary: None,
        secondary: None,
        arbitrary: pairs,
    };

    Ok(VerificationKey::from(pubkey_op.compute()?))
}
