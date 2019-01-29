//! Implementation of a Schnorr signature protocol with aggregation support.

#![allow(non_snake_case)]

use bulletproofs::PedersenGens;
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

        let mut pairs = pubkeys
            .iter()
            .map(|p| {
                let x = transcript.challenge_scalar(b"x");
                (x, *p)
            })
            .collect::<Vec<_>>();

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

    /// Creates a signature for a single private key
    pub fn sign_single(transcript: &mut Transcript, privkey: Scalar) -> Self {
        Signature::sign_aggregated(transcript, &[privkey])
    }

    /// Creates an aggregated signature for a set of private keys
    pub fn sign_aggregated(transcript: &mut Transcript, privkeys: &[Scalar]) -> Self {
        // Derive public keys from privkeys
        let gens = PedersenGens::default();
        let pubkeys = privkeys
            .iter()
            .map(|p| (p * gens.B).compress())
            .collect::<Vec<_>>();

        // Commit pubkeys
        let n = pubkeys.len();
        transcript.commit_u64(b"n", n as u64);
        for p in pubkeys.iter() {
            transcript.commit_point(b"P", p);
        }

        // Generate aggregated private key
        let aggregated_privkey: Scalar = privkeys
            .iter()
            .map(|p| {
                let x = transcript.challenge_scalar(b"x");
                p * x
            })
            .sum();

        // Generate secret nonce
        let mut rng = transcript
            .build_rng()
            .commit_witness_bytes(b"privkey", aggregated_privkey.as_bytes())
            .finalize(&mut rand::thread_rng());
        let r = Scalar::random(&mut rng);

        // Commit the nonce to the transcript
        let R = (r * gens.B).compress();
        transcript.commit_point(b"R", &R);

        // Compute challenge scalar
        let e = transcript.challenge_scalar(b"e");
        let s = r + e * aggregated_privkey;

        Signature { R, s }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let gens = PedersenGens::default();
        let mut transcript = Transcript::new(b"empty");
        let sig = Signature::sign_aggregated(&mut transcript, &[]);
        assert!(sig
            .verify_aggregated(&mut transcript, &[])
            .verify(&gens)
            .is_ok());
    }

    #[test]
    fn single_signature() {
        let gens = PedersenGens::default();

        let (pubkey, sig) = {
            let privkey = Scalar::random(&mut rand::thread_rng());
            let pubkey = (privkey * gens.B).compress();
            let mut transcript = Transcript::new(b"single_signature");
            let sig = Signature::sign_single(&mut transcript, privkey);
            (pubkey, sig)
        };

        let mut transcript = Transcript::new(b"single_signature");
        assert!(sig
            .verify_single(&mut transcript, pubkey)
            .verify(&gens)
            .is_ok());
    }

    #[test]
    fn single_signature_wrong_key() {
        let gens = PedersenGens::default();

        let sig = {
            let privkey = Scalar::random(&mut rand::thread_rng());
            let mut transcript = Transcript::new(b"single_signature");
            let sig = Signature::sign_single(&mut transcript, privkey);
            sig
        };

        let mut transcript = Transcript::new(b"single_signature");
        let wrong_pubkey = (Scalar::random(&mut rand::thread_rng()) * gens.B).compress();
        assert!(sig
            .verify_single(&mut transcript, wrong_pubkey)
            .verify(&gens)
            .is_err());
    }

    #[test]
    fn two_key_signature() {
        let gens = PedersenGens::default();

        let (pubkey1, pubkey2, sig) = {
            let privkey1 = Scalar::random(&mut rand::thread_rng());
            let pubkey1 = (privkey1 * gens.B).compress();
            let privkey2 = Scalar::random(&mut rand::thread_rng());
            let pubkey2 = (privkey2 * gens.B).compress();
            let mut transcript = Transcript::new(b"two_key_signature");
            let sig = Signature::sign_aggregated(&mut transcript, &[privkey1, privkey2]);
            (pubkey1, pubkey2, sig)
        };

        let mut transcript = Transcript::new(b"two_key_signature");
        assert!(sig
            .verify_aggregated(&mut transcript, &[pubkey1, pubkey2])
            .verify(&gens)
            .is_ok());
    }

    #[test]
    fn two_key_signature_wrong_order() {
        let gens = PedersenGens::default();

        let (pubkey1, pubkey2, sig) = {
            let privkey1 = Scalar::random(&mut rand::thread_rng());
            let pubkey1 = (privkey1 * gens.B).compress();
            let privkey2 = Scalar::random(&mut rand::thread_rng());
            let pubkey2 = (privkey2 * gens.B).compress();
            let mut transcript = Transcript::new(b"two_key_signature");
            let sig = Signature::sign_aggregated(&mut transcript, &[privkey1, privkey2]);
            (pubkey1, pubkey2, sig)
        };

        let mut transcript = Transcript::new(b"two_key_signature");
        assert!(sig
            .verify_aggregated(&mut transcript, &[pubkey2, pubkey1])
            .verify(&gens)
            .is_err());
    }
}
