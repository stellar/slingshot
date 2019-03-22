use super::counterparty::NonceCommitment;
use super::VerificationKey;
use crate::errors::VMError;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[derive(Debug, Clone)]
pub struct Signature {
    pub s: Scalar,
    pub R: CompressedRistretto,
}

impl Signature {
    pub fn sign_single(transcript: &mut Transcript, privkey: Scalar) -> Signature {
        let X = VerificationKey::from_secret(&privkey); // pubkey

        let mut rng = transcript
            .build_rng()
            .commit_witness_bytes(b"x", &privkey.to_bytes())
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r, R). r is a random nonce.
        let r = Scalar::random(&mut rng);
        // R = generator * r
        let R = NonceCommitment::new(RISTRETTO_BASEPOINT_POINT * r);

        let c = {
            transcript.commit_point(b"X", X.as_compressed_point());
            transcript.commit_point(b"R", &R.compress());
            transcript.challenge_scalar(b"c")
        };

        let s = r + c * privkey;

        Signature { s, R: R.compress() }
    }

    pub fn verify(&self, transcript: &mut Transcript, X: VerificationKey) -> Result<(), VMError> {
        let G = RISTRETTO_BASEPOINT_POINT;

        // Make c = H(X, R, m)
        // The message `m` has already been fed into the transcript
        let c = {
            transcript.commit_point(b"X", X.as_compressed_point());
            transcript.commit_point(b"R", &self.R);
            transcript.challenge_scalar(b"c")
        };

        let R = self.R.decompress().ok_or(VMError::InvalidPoint)?;

        // Check sG = R + c * X
        if self.s * G == R + c * X.into_point() {
            Ok(())
        } else {
            Err(VMError::PointOperationsFailed)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::errors::VMError;
    use crate::signature::signer::*;
    use crate::signature::{multikey::Multikey, VerificationKey};
    use curve25519_dalek::ristretto::CompressedRistretto;

    #[test]
    fn sign_verify_single() {
        let privkey = Scalar::from(1u64);
        let sig = Signature::sign_single(&mut Transcript::new(b"example transcript"), privkey);

        let X = VerificationKey::from_secret(&privkey);

        assert!(sig
            .verify(&mut Transcript::new(b"example transcript"), X)
            .is_ok());

        let priv_bad = Scalar::from(2u64);
        let X_bad = VerificationKey::from_secret(&priv_bad);
        assert!(sig
            .verify(&mut Transcript::new(b"example transcript"), X_bad)
            .is_err());
        assert!(sig
            .verify(&mut Transcript::new(b"invalid transcript"), X)
            .is_err());
    }

    #[test]
    fn sign_single_multi() {
        let privkey = Scalar::from(1u64);
        let privkeys = vec![privkey];
        let multikey = multikey_helper(&privkeys);
        let sig = sign_helper(
            privkeys,
            multikey.clone(),
            Transcript::new(b"example transcript"),
        )
        .unwrap();

        assert!(sig
            .verify(
                &mut Transcript::new(b"example transcript"),
                multikey.aggregated_key()
            )
            .is_ok());
    }

    #[test]
    fn make_aggregated_pubkey() {
        // super secret, sshhh!
        let priv_keys = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        let multikey = multikey_helper(&priv_keys);

        let expected_pubkey = CompressedRistretto::from_slice(&[
            56, 92, 251, 79, 34, 221, 181, 222, 11, 112, 55, 45, 154, 242, 40, 250, 247, 1, 109,
            126, 150, 210, 181, 6, 117, 95, 44, 102, 38, 28, 144, 49,
        ]);

        assert_eq!(expected_pubkey, multikey.aggregated_key().into_compressed());
    }

    fn multikey_helper(priv_keys: &Vec<Scalar>) -> Multikey {
        let G = RISTRETTO_BASEPOINT_POINT;
        Multikey::new(
            priv_keys
                .iter()
                .map(|priv_key| VerificationKey::from(G * priv_key))
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn sign_message() {
        // super secret, sshhh!
        let priv_keys = vec![
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        let multikey = multikey_helper(&priv_keys);

        sign_helper(priv_keys, multikey, Transcript::new(b"example transcript")).unwrap();
    }

    fn sign_helper(
        privkeys: Vec<Scalar>,
        multikey: Multikey,
        transcript: Transcript,
    ) -> Result<Signature, VMError> {
        let pubkeys: Vec<_> = privkeys
            .iter()
            .map(|privkey| VerificationKey::from(privkey * RISTRETTO_BASEPOINT_POINT))
            .collect();

        let mut transcripts: Vec<_> = pubkeys.iter().map(|_| transcript.clone()).collect();

        let (parties, precomms): (Vec<_>, Vec<_>) = privkeys
            .clone()
            .into_iter()
            .zip(transcripts.iter_mut())
            .map(|(x_i, transcript)| Party::new(transcript, x_i, multikey.clone(), pubkeys.clone()))
            .unzip();

        let (parties, comms): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_precommitments(precomms.clone()))
            .unzip();

        let (parties, shares): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .map(|p| p.receive_commitments(comms.clone()).unwrap())
            .unzip();

        let signatures: Vec<_> = parties
            .into_iter()
            .map(|p: PartyAwaitingShares| p.receive_shares(shares.clone()).unwrap())
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
            Scalar::from(1u64),
            Scalar::from(2u64),
            Scalar::from(3u64),
            Scalar::from(4u64),
        ];
        let multikey = multikey_helper(&priv_keys);

        let signature = sign_helper(
            priv_keys,
            multikey.clone(),
            Transcript::new(b"example transcript"),
        )
        .unwrap();

        assert!(signature
            .verify(
                &mut Transcript::new(b"example transcript"),
                multikey.aggregated_key()
            )
            .is_ok());
    }
}
