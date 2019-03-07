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
pub struct MultiKey(Vec<PubKey>); // TODO: also include Option<Scalar> for signing key?
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

impl MultiKey {
    pub fn aggregate(&self, transcript: &mut Transcript) -> (PubKey, PubKeyHash) {
        // L = H(X_1 || X_2 || ... || X_n)
        for X_i in &self.0 {
            transcript.commit_point(b"X_i.L", &X_i.0.compress());
        }
        let L = transcript.challenge_scalar(b"L");

        // X = sum_i ( a_i * X_i )
        // a_i = H(L, X_i)
        let mut X = RistrettoPoint::default();
        for X_i in &self.0 {
            let mut a_i_transcript = transcript.clone();
            a_i_transcript.commit_point(b"X_i.X", &X_i.0.compress());
            let a_i = a_i_transcript.challenge_scalar(b"a_i");
            X = X + a_i * X_i.0;
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

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
    use curve25519_dalek::ristretto::CompressedRistretto;

    #[test]
    fn make_aggregated_pubkey() {
        // super secret, sshhh!
        let priv_keys = vec![
            PrivKey(Scalar::from(1u64)),
            PrivKey(Scalar::from(2u64)),
            PrivKey(Scalar::from(3u64)),
            PrivKey(Scalar::from(4u64)),
        ];
        let (pub_key, pub_key_hash) = agg_pubkey_helper(&priv_keys);

        let expected_pub_key = CompressedRistretto::from_slice(&[
            130, 18, 226, 231, 233, 237, 157, 84, 32, 224, 131, 198, 42, 230, 208, 160, 173, 151,
            69, 90, 5, 12, 146, 65, 179, 6, 165, 87, 41, 106, 178, 12,
        ]);
        let expected_pub_key_hash = Scalar::from_bits([
            117, 94, 182, 185, 8, 30, 150, 65, 198, 231, 112, 232, 131, 203, 40, 235, 225, 120, 17,
            229, 216, 77, 98, 51, 230, 53, 250, 192, 247, 82, 234, 3,
        ]);

        assert_eq!(expected_pub_key, pub_key.0.compress());
        assert_eq!(expected_pub_key_hash, pub_key_hash.0);
    }

    fn agg_pubkey_helper(priv_keys: &Vec<PrivKey>) -> (PubKey, PubKeyHash) {
        let G = RISTRETTO_BASEPOINT_POINT;
        let multi_key = MultiKey(
            priv_keys
                .iter()
                .map(|priv_key| PubKey(G * priv_key.0))
                .collect(),
        );
        let mut transcript = Transcript::new(b"test");
        multi_key.aggregate(&mut transcript)
    }

    #[test]
    fn sign_message() {}
}
