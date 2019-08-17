use core::iter;
use core::borrow::Borrow;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use schnorr::{VerificationKey,Signature,SchnorrError,BatchVerification,SingleVerifier,TranscriptProtocol};

use super::{Multimessage, MusigContext,MusigError};

/// Extension trait for `schnorr::Signature`.
pub trait Multisignature {

    /// Creates a multi-message signature.
    fn sign_multi<P, M>(
        privkeys: P,
        messages: Vec<(VerificationKey, M)>,
        transcript: &mut Transcript,
    ) -> Result<Signature, MusigError>
    where
        M: AsRef<[u8]>,
        P: IntoIterator,
        P::Item: Borrow<Scalar>,
        P::IntoIter: ExactSizeIterator;

    /// Verifies a multi-message signature.
    fn verify_multi<M: AsRef<[u8]>>(
        &self,
        transcript: &mut Transcript,
        messages: Vec<(VerificationKey, M)>,
    ) -> Result<(),SchnorrError>;

    /// Verifies a multi-message signature in a batch.
    fn verify_multi_batched<M: AsRef<[u8]>>(
        &self,
        transcript: &mut Transcript,
        messages: Vec<(VerificationKey, M)>,
        batch: &mut impl BatchVerification,
    );
}

impl Multisignature for Signature {

    fn sign_multi<P, M>(
        privkeys: P,
        messages: Vec<(VerificationKey, M)>,
        transcript: &mut Transcript,
    ) -> Result<Signature, MusigError>
    where
        M: AsRef<[u8]>,
        P: IntoIterator,
        P::Item: Borrow<Scalar>,
        P::IntoIter: ExactSizeIterator,
    {
        let mut privkeys = privkeys.into_iter().peekable();

        if messages.len() != privkeys.len() {
            return Err(MusigError::BadArguments);
        }
        if privkeys.len() == 0 {
            return Err(MusigError::BadArguments);
        }

        let context = Multimessage::new(messages);

        let mut rng = transcript
            .build_rng()
            // Use one key that has enough entropy to seed the RNG.
            // We can call unwrap because we know that the privkeys length is > 0.
            .rekey_with_witness_bytes(b"x_i", privkeys.peek().unwrap().borrow().as_bytes())
            .finalize(&mut rand::thread_rng());

        // Generate ephemeral keypair (r, R). r is a random nonce.
        let r = Scalar::random(&mut rng);
        // R = generator * r
        let R = (RISTRETTO_BASEPOINT_POINT * r).compress();

        // Commit the context, and commit the nonce sum with label "R"
        context.commit(transcript);
        transcript.commit_point(b"R", &R);

        // Generate signature: s = r + sum{c_i * x_i}
        let mut s = r;
        for (i, x_i) in privkeys.enumerate() {
            let mut t = transcript.clone();
            let c_i = context.challenge(i, &mut t);
            s = s + c_i * x_i.borrow();
        }

        Ok(Signature { s, R })
    }


    /// Verifies a signature for a multimessage context
    fn verify_multi<M: AsRef<[u8]>>(
        &self,
        transcript: &mut Transcript,
        messages: Vec<(VerificationKey, M)>,
    ) -> Result<(),SchnorrError> {
        SingleVerifier::verify(|verifier| {
            self.verify_multi_batched(transcript, messages, verifier)
        })
    }

    fn verify_multi_batched<M: AsRef<[u8]>>(
        &self,
        transcript: &mut Transcript,
        messages: Vec<(VerificationKey, M)>,
        batch: &mut impl BatchVerification,
    ) {
        let context = Multimessage::new(messages);
        context.commit(transcript);
        transcript.commit_point(b"R", &self.R);

        // Form the final linear combination:
        // `s * G = R + sum{c_i * X_i}`
        //      ->
        // `0 == (-s * G) + (1 * R) + sum{c_i * X_i}`
        batch.append(
            -self.s,
            iter::once(Scalar::one()),
            iter::once(self.R.decompress()),
        );
        
        for i in 0..context.len() {
            let c_i = context.challenge(i, transcript);
            batch.append(
                Scalar::zero(), // TBD: change to Option<Item>
                iter::once(c_i),
                iter::once(Some(context.key(i).into_point())) // TBD: change to single point, not iterator
            )
        }
    }

}
