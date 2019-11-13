use core::iter;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;

use merlin::Transcript;

use super::batch::{BatchVerification, SingleVerifier};
use super::errors::StarsigError;
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
            transcript.starsig_domain_sep();
            transcript.append_point(b"X", X.as_point());
            transcript.append_point(b"R", &R);
            transcript.challenge_scalar(b"c")
        };

        let s = r + c * privkey;

        Signature { s, R }
    }

    /// Verifies the signature over a transcript using the provided verification key.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify(
        &self,
        transcript: &mut Transcript,
        pubkey: VerificationKey,
    ) -> Result<(), StarsigError> {
        SingleVerifier::verify(|verifier| self.verify_batched(transcript, pubkey, verifier))
    }

    /// Verifies the signature against a given verification key in a batch.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify_batched(
        &self,
        transcript: &mut Transcript,
        pubkey: VerificationKey,
        batch: &mut impl BatchVerification,
    ) {
        // Make c = H(pubkey, R, m)
        // The message has already been fed into the transcript
        let c = {
            transcript.starsig_domain_sep();
            transcript.append_point(b"X", pubkey.as_point());
            transcript.append_point(b"R", &self.R);
            transcript.challenge_scalar(b"c")
        };

        // Form the final linear combination:
        // `s * G = R + c * pubkey`
        //      ->
        // `0 == (-s * G) + (1 * R) + (c * pubkey)`
        batch.append(
            -self.s,
            iter::once(Scalar::one()).chain(iter::once(c)),
            iter::once(self.R.decompress()).chain(iter::once(pubkey.into_point().decompress())),
        );
    }
}

// Message-oriented API
impl Signature {
    /// Signs a message with a given domain-separation label.
    /// This is a simpler byte-oriented API over more flexible Transcript-based API.
    /// Internally it creates a Transcript instance labelled "Starsig.sign_message",
    /// and appends to it message bytes labelled with a user-provided `label`.
    pub fn sign_message(label: &'static [u8], message: &[u8], privkey: Scalar) -> Signature {
        Self::sign(&mut Self::transcript_for_message(label, message), privkey)
    }

    /// Verifies the signature over a message using the provided verification key.
    /// Internally it creates a Transcript instance labelled "Starsig.sign_message",
    /// and appends to it message bytes labelled with a user-provided `label`.
    pub fn verify_message(
        &self,
        label: &'static [u8],
        message: &[u8],
        pubkey: VerificationKey,
    ) -> Result<(), StarsigError> {
        self.verify(&mut Self::transcript_for_message(label, message), pubkey)
    }

    /// Verifies the signature over a message using the provided verification key.
    /// Transcript should be in the same state as it was during the `sign` call
    /// that created the signature.
    pub fn verify_message_batched(
        &self,
        label: &'static [u8],
        message: &[u8],
        pubkey: VerificationKey,
        batch: &mut impl BatchVerification,
    ) {
        self.verify_batched(
            &mut Self::transcript_for_message(label, message),
            pubkey,
            batch,
        )
    }

    fn transcript_for_message(label: &'static [u8], message: &[u8]) -> Transcript {
        let mut t = Transcript::new(b"Starsig.sign_message");
        t.append_message(label, message);
        t
    }
}
