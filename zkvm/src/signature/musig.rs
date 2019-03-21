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
    pub fn sign_single(inp_transcript: &Transcript, privkey: Scalar) -> Signature {
        let mut transcript = inp_transcript.clone();
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
            transcript.commit_point(b"X", &X.0);
            transcript.commit_point(b"R", &R.compress());
            transcript.challenge_scalar(b"c")
        };

        let s = r + c * privkey;

        Signature { s, R: R.compress() }
    }

    pub fn verify(&self, transcript: &Transcript, X: VerificationKey) -> Result<(), VMError> {
        let G = RISTRETTO_BASEPOINT_POINT;
        let mut transcript = transcript.clone();

        // Make c = H(X, R, m)
        // The message `m` has already been fed into the transcript
        let c = {
            transcript.commit_point(b"X", &X.0);
            transcript.commit_point(b"R", &self.R);
            transcript.challenge_scalar(b"c")
        };

        let X = X.0.decompress().ok_or(VMError::InvalidPoint)?;
        let R = self.R.decompress().ok_or(VMError::InvalidPoint)?;

        // Check sG = R + c * X
        if self.s * G == R + c * X {
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
        let mut transcript = Transcript::new(b"oh hello");
        transcript.commit_bytes(b"label", b"message");
        let sig = Signature::sign_single(&transcript, privkey);

        let X = VerificationKey::from_secret(&privkey);

        assert!(sig.verify(&transcript, X).is_ok());

        let priv_bad = Scalar::from(2u64);
        let X_bad = VerificationKey::from_secret(&priv_bad);
        assert!(sig.verify(&transcript, X_bad).is_err());

        let mut transcript_bad = Transcript::new(b"oh goodbye");
        transcript_bad.commit_bytes(b"label", b"message");
        assert!(sig.verify(&transcript_bad, X).is_err());
    }

    #[test]
    fn sign_single_multi() {
        let privkey = Scalar::from(1u64);
        let privkeys = vec![privkey];
        let multikey = multikey_helper(&privkeys);
        let msg = b"message for you, sir";
        let sig = sign_helper(privkeys, multikey.clone(), msg.to_vec()).unwrap();

        let mut transcript = Transcript::new(b"signing test");
        transcript.commit_bytes(b"message", msg);

        assert!(sig.verify(&transcript, multikey.aggregated_key()).is_ok());
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

        assert_eq!(expected_pubkey, multikey.aggregated_key().0);
    }

    fn multikey_helper(priv_keys: &Vec<Scalar>) -> Multikey {
        let G = RISTRETTO_BASEPOINT_POINT;
        Multikey::new(
            priv_keys
                .iter()
                .map(|priv_key| VerificationKey((G * priv_key).compress()))
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
        let m = b"message to sign".to_vec();

        sign_helper(priv_keys, multikey, m).unwrap();
    }

    fn sign_helper(
        privkeys: Vec<Scalar>,
        multikey: Multikey,
        m: Vec<u8>,
    ) -> Result<Signature, VMError> {
        let mut transcript = Transcript::new(b"signing test");
        transcript.commit_bytes(b"message", &m);
        let pubkeys: Vec<_> = privkeys
            .iter()
            .map(|privkey| VerificationKey((privkey * RISTRETTO_BASEPOINT_POINT).compress()))
            .collect();

        let (parties, precomms): (Vec<_>, Vec<_>) = privkeys
            .clone()
            .into_iter()
            .map(|x_i| Party::new(&transcript.clone(), x_i, multikey.clone(), pubkeys.clone()))
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
        let m = b"message to sign".to_vec();

        let signature = sign_helper(priv_keys, multikey.clone(), m.clone()).unwrap();

        let mut transcript = Transcript::new(b"signing test");
        transcript.commit_bytes(b"message", &m);

        assert!(signature
            .verify(&mut transcript, multikey.aggregated_key())
            .is_ok());
    }
}
