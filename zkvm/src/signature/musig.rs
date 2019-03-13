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

#[derive(Clone)]
pub struct Message(pub Vec<u8>);

impl Signature {
    pub fn verify(
        &self,
        // The message `m` should already have been fed into the transcript
        transcript: &Transcript,
        aggregated_key: VerificationKey,
    ) -> Result<(), VMError> {
        let G = RISTRETTO_BASEPOINT_POINT;
        let mut transcript = transcript.clone();

        // Make c = H(aggregated_key, R, m)
        // The message `m` should already have been fed into the transcript
        let c = {
            transcript.commit_point(b"aggregated_key", &aggregated_key.0);
            transcript.commit_point(b"R", &self.R.compress());
            transcript.challenge_scalar(b"c")
        };

        let aggregated_key = match aggregated_key.0.decompress() {
            Some(aggregated_key) => aggregated_key,
            None => return Err(VMError::InvalidPoint),
        };
        // Check sG = R + c * aggregated_key
        match self.s * G == self.R + c * aggregated_key {
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
            66, 159, 16, 236, 165, 170, 29, 154, 226, 5, 197, 204, 148, 244, 75, 6, 182, 23, 35,
            23, 237, 90, 147, 172, 26, 104, 172, 191, 183, 57, 16, 31,
        ]);

        assert_eq!(expected_pub_key, multikey.aggregated_key().0);
    }

    fn multikey_helper(priv_keys: &Vec<PrivKey>) -> Option<Multikey> {
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

        sign_helper(priv_keys, multikey, m).unwrap();
    }

    fn sign_helper(
        priv_keys: Vec<PrivKey>,
        multikey: Multikey,
        m: Message,
    ) -> Result<Signature, VMError> {
        let mut transcript = Transcript::new(b"signing test");
        transcript.commit_bytes(b"message", &m.0);

        let (parties, precomms): (Vec<_>, Vec<_>) = priv_keys
            .clone()
            .into_iter()
            .map(|x_i| PartyAwaitingPrecommitments::new(&transcript.clone(), x_i, multikey.clone()))
            .unzip();

        let (parties, comms): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_precommitments(precomms.clone()))
            .unzip();

        let (parties, siglets): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_commitments(comms.clone()).unwrap())
            .unzip();

        let pub_keys: Vec<_> = priv_keys
            .iter()
            .map(|priv_key| PubKey(priv_key.0 * RISTRETTO_BASEPOINT_POINT))
            .collect();
        let signatures: Vec<_> = parties
            .into_iter()
            .map(|p: PartyAwaitingSiglets| {
                p.receive_and_verify_siglets(siglets.clone(), pub_keys.clone())
            })
            .collect();

        // Check that signatures from all parties are the same
        let cmp = &signatures[0];
        for sig in &signatures {
            assert_eq!(cmp.s, sig.s);
            assert_eq!(cmp.R, sig.R)
        }

        Ok(signatures[0].clone())
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

        let signature = sign_helper(priv_keys, multikey.clone(), m.clone()).unwrap();

        let mut transcript = Transcript::new(b"signing test");
        transcript.commit_bytes(b"message", &m.0);

        assert!(signature
            .verify(&mut transcript, multikey.aggregated_key())
            .is_ok());
    }
}
