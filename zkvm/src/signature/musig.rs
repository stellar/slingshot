#![allow(non_snake_case)]

use crate::errors::VMError;
use crate::signature::VerificationKey;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[derive(Clone)]
pub struct PubKey(pub RistrettoPoint);

#[derive(Clone)]
pub struct PrivKey(pub Scalar);

#[derive(Debug, Clone)]
pub struct Signature {
    pub s: Scalar,
    pub R: RistrettoPoint,
}

// TODO: is this actually the msg format we want?
#[derive(Clone)]
pub struct Message(pub Vec<u8>);

impl Signature {
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        X_agg: VerificationKey,
        m: Message,
    ) -> Result<(), VMError> {
        let G = RISTRETTO_BASEPOINT_POINT;

        // Make c = H(X_agg, R, m)
        let c = {
            transcript.commit_point(b"X_agg", &X_agg.0);
            transcript.commit_point(b"R", &self.R.compress());
            transcript.commit_bytes(b"m", &m.0);
            transcript.challenge_scalar(b"c")
        };

        let X_agg = match X_agg.0.decompress() {
            Some(X_agg) => X_agg,
            None => return Err(VMError::InvalidPoint),
        };
        // Check sG = R + c * X_agg
        match self.s * G == self.R + c * X_agg {
            true => Ok(()),
            false => Err(VMError::PointOperationsFailed),
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::errors::VMError;
    use crate::signature::prover::*;
    use crate::signature::{multikey::Multikey, VerificationKey};
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
        let multikey = multikey_helper(&priv_keys).unwrap();

        let expected_pub_key = CompressedRistretto::from_slice(&[
            130, 18, 226, 231, 233, 237, 157, 84, 32, 224, 131, 198, 42, 230, 208, 160, 173, 151,
            69, 90, 5, 12, 146, 65, 179, 6, 165, 87, 41, 106, 178, 12,
        ]);
        let expected_pub_key_hash = Scalar::from_bits([
            117, 94, 182, 185, 8, 30, 150, 65, 198, 231, 112, 232, 131, 203, 40, 235, 225, 120, 17,
            229, 216, 77, 98, 51, 230, 53, 250, 192, 247, 82, 234, 3,
        ]);

        assert_eq!(expected_pub_key, multikey.aggregated_key().0);
        assert_eq!(expected_pub_key_hash, multikey.aggregated_hash());
    }

    fn multikey_helper(priv_keys: &Vec<PrivKey>) -> Result<Multikey, VMError> {
        let G = RISTRETTO_BASEPOINT_POINT;
        Multikey::new(
            priv_keys
                .iter()
                .map(|priv_key| VerificationKey((G * priv_key.0).compress()))
                .collect(),
        )
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
        let multikey = multikey_helper(&priv_keys).unwrap();
        let m = Message(b"message to sign".to_vec());

        sign_helper(priv_keys, multikey, m);
    }

    fn sign_helper(priv_keys: Vec<PrivKey>, multikey: Multikey, m: Message) -> Signature {
        let (parties, precomms): (Vec<_>, Vec<_>) = priv_keys
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, x_i)| {
                PartyAwaitingPrecommitments::new(
                    &Transcript::new(b"signing.test"),
                    x_i,
                    multikey.clone(),
                )
            })
            .unzip();

        let (parties, comms): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_precommitments(precomms.clone()))
            .unzip();

        let (parties, siglets): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_commitments(m.clone(), comms.clone()))
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
        let multikey = multikey_helper(&priv_keys).unwrap();
        let m = Message(b"message to sign".to_vec());

        let signature = sign_helper(priv_keys, multikey.clone(), m.clone());

        let mut verify_transcript = Transcript::new(b"signing.test");
        assert!(signature
            .verify(&mut verify_transcript, multikey.aggregated_key(), m)
            .is_ok());
    }
}
