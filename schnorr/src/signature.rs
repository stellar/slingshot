use super::deferred_verification::DeferredVerification;
use super::errors::SchnorrError;
use super::key::VerificationKey;
use super::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

/// A Schnorr signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    /// Signature using nonce, message, and private key
    pub s: Scalar,
    /// Nonce commitment
    pub R: CompressedRistretto,
}

impl Signature {
    /// Creates a signature for a single private key and single message
    pub fn sign(transcript: &mut Transcript, privkey: Scalar) -> Signature {
        let X = VerificationKey::from_secret(&privkey); // pubkey

        let mut rng = transcript
            .build_rng()
            .rekey_with_witness_bytes(b"x", &privkey.to_bytes())
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r, R). r is a random nonce.
        let r = Scalar::random(&mut rng);
        // R = generator * r
        let R = (RISTRETTO_BASEPOINT_POINT * r).compress();

        let c = {
            transcript.schnorr_sig_domain_sep();
            transcript.commit_point(b"X", X.as_compressed());
            transcript.commit_point(b"R", &R);
            transcript.challenge_scalar(b"c")
        };

        let s = r + c * privkey;

        Signature { s, R }
    }

    /// Verifies the signature against a given verification key.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify(&self, transcript: &mut Transcript, X: VerificationKey) -> Result<(),SchnorrError> {
        self.verify_deferred(transcript, X).verify()
    }

    /// Computes a `DeferredVerification` object for verifying this signature in a batch.
    /// To verify immediately, use `verify`.
    pub fn verify_deferred(&self, transcript: &mut Transcript, X: VerificationKey) -> DeferredVerification {
        // Make c = H(X, R, m)
        // The message `m` has already been fed into the transcript
        let c = {
            transcript.schnorr_sig_domain_sep();
            transcript.commit_point(b"X", X.as_compressed());
            transcript.commit_point(b"R", &self.R);
            transcript.challenge_scalar(b"c")
        };

        // Form the final linear combination:
        // `s * G = R + c * X`
        //      ->
        // `0 == (-s * G) + (1 * R) + (c * X)`
        DeferredVerification {
            static_point_weight: -self.s,
            dynamic_point_weights: vec![(Scalar::one(), self.R.decompress()), (c, Some(X.into_point()))],
        }
    }

    /// Decodes a signature from 64-byte array.
    pub fn from_bytes(sig: [u8; 64]) -> Result<Self, SchnorrError> {
        let mut Rbuf = [0u8; 32];
        let mut sbuf = [0u8; 32];
        Rbuf[..].copy_from_slice(&sig[..32]);
        sbuf[..].copy_from_slice(&sig[32..]);
        Ok(Signature {
            R: CompressedRistretto(Rbuf),
            s: Scalar::from_canonical_bytes(sbuf).ok_or(SchnorrError::InvalidSignature)?,
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

    #[test]
    fn sign_and_verify() {
        let privkey = Scalar::from(1u64);
        let sig = Signature::sign(&mut Transcript::new(b"example transcript"), privkey);

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
}
