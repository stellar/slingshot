use super::counterparty::NonceCommitment;
use super::deferred_verification::DeferredVerification;
use super::errors::MusigError;
use super::key::VerificationKey;
use super::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// A Schnorr signature.
#[derive(Debug, Clone)]
pub struct Signature {
    /// Signature using nonce, message, and private key
    pub s: Scalar,
    /// Nonce commitment
    pub R: CompressedRistretto,
}

impl Signature {
    /// Creates a signature for a single private key, bypassing the party state transitions
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

    /// Verifies a signature for a single VerificationKey
    pub fn verify(&self, transcript: &mut Transcript, X: VerificationKey) -> DeferredVerification {
        // Make c = H(X, R, m)
        // The message `m` has already been fed into the transcript
        let c = {
            transcript.commit_point(b"X", X.as_compressed_point());
            transcript.commit_point(b"R", &self.R);
            transcript.challenge_scalar(b"c")
        };

        // Form the final linear combination:
        // `s * G = R + c * X`
        //      ->
        // `0 == (-s * G) + (1 * R) + (c * X)`
        DeferredVerification {
            static_point_weight: -self.s,
            dynamic_point_weights: vec![(Scalar::one(), self.R), (c, X.into_compressed())],
        }
    }

    /// Decodes a signature from 64-byte array.
    pub fn from_bytes(sig: [u8; 64]) -> Result<Self, MusigError> {
        let mut Rbuf = [0u8; 32];
        let mut sbuf = [0u8; 32];
        Rbuf[..].copy_from_slice(&sig[..32]);
        sbuf[..].copy_from_slice(&sig[32..]);
        Ok(Signature {
            R: CompressedRistretto(Rbuf),
            s: Scalar::from_canonical_bytes(sbuf).ok_or(MusigError::BadArguments)?,
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
    use crate::errors::MusigError;
    use crate::key::{Multikey, VerificationKey};
    use crate::signer::*;
    use curve25519_dalek::ristretto::CompressedRistretto;

    #[test]
    fn sign_verify_single() {
        let privkey = Scalar::from(1u64);
        let sig = Signature::sign_single(&mut Transcript::new(b"example transcript"), privkey);

        let X = VerificationKey::from_secret(&privkey);

        assert!(sig
            .verify(&mut Transcript::new(b"example transcript"), X)
            .verify()
            .is_ok());

        let priv_bad = Scalar::from(2u64);
        let X_bad = VerificationKey::from_secret(&priv_bad);
        assert!(sig
            .verify(&mut Transcript::new(b"example transcript"), X_bad)
            .verify()
            .is_err());
        assert!(sig
            .verify(&mut Transcript::new(b"invalid transcript"), X)
            .verify()
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
            .verify()
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
            60, 118, 86, 112, 148, 29, 45, 106, 212, 7, 119, 198, 76, 112, 161, 226, 21, 242, 242,
            170, 66, 127, 36, 62, 160, 233, 199, 29, 206, 18, 250, 67,
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
    ) -> Result<Signature, MusigError> {
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

        let signatures: Vec<Signature> = parties
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
            .verify()
            .is_ok());
    }
}
