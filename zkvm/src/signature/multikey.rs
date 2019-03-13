use crate::errors::VMError;
use crate::signature::VerificationKey;
use crate::transcript::TranscriptProtocol;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[derive(Clone)]
pub struct Multikey {
    transcript: Transcript,
    X_agg: VerificationKey,
}

impl Multikey {
    pub fn new(pubkeys: Vec<VerificationKey>) -> Result<Self, VMError> {
        // Create transcript for Multikey
        let mut transcript = Transcript::new(b"ZkVM.aggregated-key");

        // Hash in pubkeys
        // L = H(X_1 || X_2 || ... || X_n)
        for X_i in &pubkeys {
            transcript.commit_point(b"X_i.L", &X_i.0);
        }

        let mut multikey = Multikey {
            transcript,
            X_agg: VerificationKey(RistrettoPoint::default().compress()),
        };

        // Make aggregated pubkey
        // X_agg = sum_i ( a_i * X_i )
        // a_i = H(L, X_i). Compenents of L have already been fed to transcript.
        let mut X_agg = RistrettoPoint::default();
        for X_i in &pubkeys {
            let a_i = multikey.factor_for_key(X_i);
            let X_i = match X_i.0.decompress() {
                Some(X_i) => X_i,
                None => return Err(VMError::InvalidPoint),
            };
            X_agg = X_agg + a_i * X_i;
        }

        multikey.X_agg = VerificationKey(X_agg.compress());

        Ok(multikey)
    }

    // Make a_i
    pub fn factor_for_key(&self, X_i: &VerificationKey) -> Scalar {
        // a_i = H(L, X_i). Compenents of L have already been fed to transcript.
        let mut a_i_transcript = self.transcript.clone();
        a_i_transcript.commit_point(b"X_i", &X_i.0);
        a_i_transcript.challenge_scalar(b"a_i")
    }

    pub fn aggregated_key(&self) -> VerificationKey {
        self.X_agg
    }
}
