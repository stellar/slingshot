use core::iter;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

use super::batch::{BatchVerification, SingleVerifier};
use super::errors::SchnorrError;
use super::key::VerificationKey;
use super::transcript::TranscriptProtocol;

/// A Schnorr signature.
#[derive(Debug, Clone)]
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
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        X: VerificationKey,
    ) -> Result<(), SchnorrError> {
        SingleVerifier::verify(|verifier| self.verify_batched(transcript, X, verifier))
    }

    /// Verifies the signature against a given verification key in a batch.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify_batched(
        &self,
        transcript: &mut Transcript,
        X: VerificationKey,
        batch: &mut impl BatchVerification,
    ) {
        // Make c = H(X, R, m)
        // The message has already been fed into the transcript
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
        batch.append(
            -self.s,
            iter::once(Scalar::one()).chain(iter::once(c)),
            iter::once(self.R.decompress()).chain(iter::once(Some(X.into_point()))),
        );
    }
}
