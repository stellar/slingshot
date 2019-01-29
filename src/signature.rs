//! Implementation of a Schnorr signature protocol with aggregation support.

#![allow(non_snake_case)]

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::errors::VMError;
use crate::point_ops::PointOp;
use crate::transcript::TranscriptProtocol;

#[derive(Copy, Clone, Debug)]
pub struct Signature {
    R: CompressedRistretto,
    s: Scalar,
}

impl Signature {
    /// Verifies a signature for a single key
    pub fn verify_single(
        &self,
        transcript: &mut Transcript,
        pubkey: CompressedRistretto,
    ) -> PointOp {
        self.verify_aggregated(transcript, &[pubkey])
    }

    /// Verifies an aggregated signature for a collection of public keys.
    pub fn verify_aggregated(
        &self,
        transcript: &mut Transcript,
        pubkeys: &[CompressedRistretto],
    ) -> PointOp {
        transcript.commit_u64(b"n", pubkeys.len() as u64);
        for p in pubkeys.iter() {
            transcript.commit_point(b"P", p);
        }

        let mut pairs: Vec<(Scalar, CompressedRistretto)> = Vec::with_capacity(pubkeys.len() + 1);

        // Skip randomization factor for the first pubkey to be more efficient in a single-key case
        if pubkeys.len() > 0 {
            pairs.push((Scalar::one(), pubkeys[0]));
        }
        // Apply randomization factors to all the other pubkeys
        let i: usize = 1;
        while i < pubkeys.len() {
            let x = transcript.challenge_scalar(b"x");
            pairs.push((x, pubkeys[i]));
        }

        // Commit the signature's nonce commitment
        transcript.commit_point(b"R", &self.R);

        // Get the Fiat-Shamir challenge
        let e = transcript.challenge_scalar(b"e");

        // Apply challenge to all the pubkeys
        for i in 0..pubkeys.len() {
            pairs[i] = (pairs[i].0 * e, pairs[i].1);
        }

        // Form the final linear combination:
        // `s*B == e*(P0 + x1*P1 + x2*P2 + ...) + R`
        //      ->
        // `0 == -s*B + e*(P0 + x1*P1 + x2*P2 + ...) + R`
        pairs.push((Scalar::one(), self.R));

        PointOp {
            primary: Some(-self.s),
            secondary: None,
            arbitrary: pairs,
        }
    }

    /// Creates an aggregated signature for a set of private keys
    pub fn sign_aggregated(&self, transcript: &mut Transcript, privkeys: &[Scalar]) -> Self {
        unimplemented!()
    }
}

// Serialization
impl Signature {
    /// Decodes a signature from 64-byte array.
    pub fn from_bytes(sig: [u8; 64]) -> Result<Self, VMError> {
        let mut Rbuf = [0u8; 32];
        let mut sbuf = [0u8; 32];
        Rbuf[..].copy_from_slice(&sig[..32]);
        sbuf[..].copy_from_slice(&sig[32..]);
        Ok(Signature {
            R: CompressedRistretto(Rbuf),
            s: Scalar::from_canonical_bytes(sbuf).ok_or(VMError::FormatError)?,
        })
    }

    /// Encodes the signature as a 64-byte array.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.R.as_bytes());
        buf[32..].copy_from_slice(self.s.as_bytes());
        buf
    }
}
