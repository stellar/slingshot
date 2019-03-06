#![allow(non_snake_case)]

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

// Modules for signing protocol

pub mod prover;

pub struct PrivKey(Scalar);
pub struct PubKey(RistrettoPoint);
pub struct MultikeyWitness(Vec<PubKey>); // TODO: also include Option<Scalar> for signing key?
pub struct PubKeyHash(Scalar);
pub struct Signature {
    s: Scalar,
    R: RistrettoPoint,
}

// TODO: come up with a better name for this!
pub struct Shared {
    generator: RistrettoPoint,
    transcript: Transcript,
    // X = sum_i ( H(L, X_i) * X_i )
    agg_pubkey: PubKey,
    // L = H(X_1 || X_2 || ... || X_n)
    agg_pubkey_hash: PubKeyHash,
    // TODO: what should the message representation format be?
    message: Vec<u8>,
}

impl MultikeyWitness {
    pub fn aggregate(&self, transcript: &mut Transcript) -> (PubKey, PubKeyHash) {
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

impl Signature {
    pub fn verify(&self, shared: Shared) -> bool {
        // Make H(X,R,m). shared.agg_pubkey = X, shared.message = m.
        let hash_X_R_m = {
            let mut hash_transcript = shared.transcript.clone();
            hash_transcript.commit_point(b"X", &shared.agg_pubkey.0.compress());
            hash_transcript.commit_point(b"R", &self.R.compress());
            hash_transcript.commit_bytes(b"m", &shared.message);
            hash_transcript.challenge_scalar(b"hash_x_R_m")
        };

        // Check sG = R + H(X,R,m)*X
        self.s * shared.generator == self.R + hash_X_R_m * shared.agg_pubkey.0
    }
}
