#![allow(non_snake_case)]

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand;

pub mod prover;

#[derive(Clone)]
pub struct PrivKey(Scalar);

#[derive(Clone)]
pub struct PubKey(RistrettoPoint);

#[derive(Clone)]
pub struct PubKeyHash(Scalar);

pub struct MultiKey(Vec<PubKey>);

#[derive(Debug, Clone)]
pub struct Signature {
    s: Scalar,
    R: RistrettoPoint,
}

// TODO: is this actually the msg format we want?
#[derive(Clone)]
pub struct Message(Vec<u8>);

impl PrivKey {
    pub fn new(s: Scalar) -> Self {
        PrivKey(s)
    }
}

impl MultiKey {
    pub fn aggregate(&self) -> (PubKey, PubKeyHash) {
        let transcript = Transcript::new(b"ZkVM.MuSig");

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
    pub fn verify(&self, X_agg: PubKey, m: Message) -> bool {
        let mut transcript = Transcript::new(b"ZkVM.MuSig");
        let G = RISTRETTO_BASEPOINT_POINT;

        // Make c = H(X_agg, R, m)
        let c = {
            transcript.commit_point(b"X_agg", &X_agg.0.compress());
            transcript.commit_point(b"R", &self.R.compress());
            transcript.commit_bytes(b"m", &m.0);
            transcript.challenge_scalar(b"c")
        };

        // Check sG = R + c * X_agg
        self.s * G == self.R + c * X_agg.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::prover::*;
    use curve25519_dalek::ristretto::CompressedRistretto;

    #[test]
    fn make_aggregated_pubkey() {
        // super secret, sshhh!
        let priv_keys = vec![
            PrivKey::new(Scalar::from(1u64)),
            PrivKey::new(Scalar::from(2u64)),
            PrivKey::new(Scalar::from(3u64)),
            PrivKey::new(Scalar::from(4u64)),
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
        multi_key.aggregate()
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
        let m = Message(b"message to sign".to_vec());

        sign_helper(priv_keys, X_agg, L, m);
    }

    fn sign_helper(priv_keys: Vec<PrivKey>, X_agg: PubKey, L: PubKeyHash, m: Message) -> Signature {
        let (parties, precomms): (Vec<_>, Vec<_>) = priv_keys
            .clone()
            .into_iter()
            .map(|x_i| PartyAwaitingPrecommitments::new(x_i, X_agg.clone(), L.clone(), m.clone()))
            .unzip();

        let (parties, comms): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_precommitments(precomms.clone()))
            .unzip();

        let (parties, siglets): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_commitments(comms.clone()))
            .unzip();

        let pub_keys: Vec<_> = priv_keys
            .iter()
            .map(|priv_key| PubKey(priv_key.0 * RISTRETTO_BASEPOINT_POINT))
            .collect();
        let signatures: Vec<_> = parties
            .into_iter()
            .map(|p| p.receive_and_verify_siglets(siglets.clone(), pub_keys.clone()))
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
        let m = Message(b"message to sign".to_vec());

        let signature = sign_helper(priv_keys, X_agg.clone(), L, m.clone());
        assert_eq!(true, signature.verify(X_agg, m));
    }
}
