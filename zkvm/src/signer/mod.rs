#![allow(non_snake_case)]

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

// Modules for signing protocol

pub mod prover;

#[derive(Clone)]
pub struct PrivKey(Scalar);

#[derive(Clone)]
pub struct PubKey(RistrettoPoint);

pub struct MultiKey(Vec<PubKey>); // TODO: also include Option<Scalar> for signing key?

#[derive(Clone)]
pub struct PubKeyHash(Scalar);

#[derive(Debug, Clone)]
pub struct Signature {
    s: Scalar,
    R: RistrettoPoint,
}

#[derive(Clone)]
pub struct Shared {
    G: RistrettoPoint,
    transcript: Transcript,
    // X_agg = sum_i ( a_i * X_i )
    X_agg: PubKey,
    // L = H(X_1 || X_2 || ... || X_n)
    L: PubKeyHash,
    // message being signed
    m: Vec<u8>,
}

impl MultiKey {
    pub fn aggregate(&self, transcript: &mut Transcript) -> (PubKey, PubKeyHash) {
        // L = H(X_1 || X_2 || ... || X_n)
        let mut L_transcript = transcript.clone();
        for X_i in &self.0 {
            L_transcript.commit_point(b"X_i.L", &X_i.0.compress());
        }
        let L = L_transcript.challenge_scalar(b"L");

        // X = sum_i ( a_i * X_i )
        // a_i = H(L, X_i)
        let mut X = RistrettoPoint::default();
        for X_i in &self.0 {
            let mut a_i_transcript = transcript.clone();
            a_i_transcript.commit_scalar(b"L", &L);
            a_i_transcript.commit_point(b"X_i", &X_i.0.compress());
            let a_i = a_i_transcript.challenge_scalar(b"a_i");
            X = X + a_i * X_i.0;
        }

        (PubKey(X), PubKeyHash(L))
    }
}

impl Signature {
    pub fn verify(&self, shared: Shared) -> bool {
        // Make c = H(X_agg, R, m)
        let c = {
            let mut hash_transcript = shared.transcript.clone();
            hash_transcript.commit_point(b"X_agg", &shared.X_agg.0.compress());
            hash_transcript.commit_point(b"R", &self.R.compress());
            hash_transcript.commit_bytes(b"m", &shared.m);
            hash_transcript.challenge_scalar(b"c")
        };

        // Check sG = R + c * X_agg
        self.s * shared.G == self.R + c * shared.X_agg.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::prover::*;
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
        let mut transcript = Transcript::new(b"agg pubkey test");
        multi_key.aggregate(&mut transcript)
    }

    #[test]
    fn sign_message() {
        // super secret, sshhh!
        let priv_keys = vec![
            PrivKey(Scalar::from(1u64)),
            PrivKey(Scalar::from(2u64)),
            PrivKey(Scalar::from(3u64)),
            PrivKey(Scalar::from(4u64)),
        ];
        let (X_agg, L) = agg_pubkey_helper(&priv_keys);

        let shared = Shared {
            G: RISTRETTO_BASEPOINT_POINT,
            transcript: Transcript::new(b"sign msg test"),
            X_agg,
            L,
            m: b"message to sign".to_vec(),
        };

        sign_helper(priv_keys, shared);
    }

    fn sign_helper(priv_keys: Vec<PrivKey>, shared: Shared) -> Signature {
        let (parties, precomms): (Vec<_>, Vec<_>) = priv_keys
            .clone()
            .into_iter()
            .map(|x_i| PartyAwaitingPrecommitments::new(x_i, shared.clone()))
            .unzip();

        let (parties, comms): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_precommitments(precomms.clone()))
            .unzip();

        let (parties, siglets): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_commitments(comms.clone()))
            .unzip();

        // Check that all siglets are valid
        for (i, s_i) in siglets.iter().enumerate() {
            let S_i = s_i.0 * shared.G;
            let X_i = priv_keys[i].0 * shared.G;
            let R_i = &comms[i].0;
            let R: RistrettoPoint = comms.iter().map(|R_i| R_i.0).sum();

            // Make c = H(X_agg, R, m)
            let c = {
                let mut hash_transcript = shared.transcript.clone();
                hash_transcript.commit_point(b"X_agg", &shared.X_agg.0.compress());
                hash_transcript.commit_point(b"R", &R.compress());
                hash_transcript.commit_bytes(b"m", &shared.m);
                hash_transcript.challenge_scalar(b"c")
            };
            // Make a_i = H(L, X_i)
            let a_i = {
                let mut hash_transcript = shared.transcript.clone();
                hash_transcript.commit_scalar(b"L", &shared.L.0);
                let X_i = priv_keys[i].0 * shared.G;
                hash_transcript.commit_point(b"X_i", &X_i.compress());
                hash_transcript.challenge_scalar(b"a_i")
            };

            // Check that S_i = R_i + c * a_i * X_i
            assert_eq!(S_i, R_i + c * a_i * X_i);
        }

        let signatures: Vec<_> = parties
            .into_iter()
            .map(|p| p.receive_siglets(siglets.clone()))
            .collect();

        // Check that signatures from all parties are the same
        let cmp = &signatures[0];
        for sig in &signatures {
            assert_eq!(cmp.s, sig.s);
            assert_eq!(cmp.R, sig.R)
        }

        (signatures[0].clone())
    }

    #[test]
    fn verify_sig() {
        // super secret, sshhh!
        let priv_keys = vec![
            PrivKey(Scalar::from(1u64)),
            PrivKey(Scalar::from(2u64)),
            PrivKey(Scalar::from(3u64)),
            PrivKey(Scalar::from(4u64)),
        ];
        let (X_agg, L) = agg_pubkey_helper(&priv_keys);

        let shared = Shared {
            G: RISTRETTO_BASEPOINT_POINT,
            transcript: Transcript::new(b"sign msg test"),
            X_agg,
            L,
            m: b"message to sign".to_vec(),
        };

        let signature = sign_helper(priv_keys, shared.clone());
        assert_eq!(true, signature.verify(shared.clone()));
    }
}
