#![allow(non_snake_case)]

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

// Modules for signing protocol

pub mod prover;
pub mod verifier;

pub struct PrivKey(Scalar);
pub struct PubKey(RistrettoPoint);
pub struct MultikeyWitness(Vec<PubKey>); // TODO: also include Option<Scalar> for signing key?
pub struct PubKeyHash(Scalar);
pub struct Signature {
    s: Scalar,
    r: RistrettoPoint,
}

// TODO: compress & decompress RistrettoPoint into CompressedRistretto when sending as messages

impl MultikeyWitness {
    fn aggregate(&self, transcript: &mut Transcript) -> (PubKey, PubKeyHash) {
        // L = H(X_1 || X_2 || ... || X_n)
        for X_i in &self.0 {
            transcript.commit_point(b"X_i.L", &X_i.0.compress());
        }
        let L = transcript.challenge_scalar(b"L");

        // X = sum_i ( H(L, X_i) * X_i )
        let mut X = RistrettoPoint::default();
        for X_i in &self.0 {
            transcript.commit_point(b"X_i.X", &X_i.0.compress());
            let hash = transcript.challenge_scalar(b"H(L,X_i)");
            X = X + hash * X_i.0;
        }

        (PubKey(X), PubKeyHash(L))
    }
}
