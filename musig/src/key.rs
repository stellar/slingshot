use super::errors::MusigError;
use super::transcript::TranscriptProtocol;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[derive(Clone)]
/// MuSig aggregated key.
pub struct Multikey {
    transcript: Option<Transcript>,
    aggregated_key: VerificationKey,
}

impl Multikey {
    /// Constructs a new MuSig multikey aggregating the pubkeys.
    pub fn new(pubkeys: Vec<VerificationKey>) -> Result<Self, MusigError> {
        match pubkeys.len() {
            0 => {
                return Err(MusigError::BadArguments);
            }
            1 => {
                return Ok(Multikey {
                    transcript: None,
                    aggregated_key: pubkeys[0],
                });
            }
            _ => {}
        }

        // Create transcript for Multikey
        let mut transcript = Transcript::new(b"Musig.aggregated-key");
        transcript.commit_u64(b"n", pubkeys.len() as u64);

        // Commit pubkeys into the transcript
        // <L> = H(X_1 || X_2 || ... || X_n)
        for X in &pubkeys {
            transcript.commit_point(b"X", X.as_compressed());
        }

        // aggregated_key = sum_i ( a_i * X_i )
        let mut aggregated_key = RistrettoPoint::default();
        for X in &pubkeys {
            let a = Multikey::compute_factor(&transcript, X);
            let X = X.into_point();
            aggregated_key = aggregated_key + a * X;
        }

        Ok(Multikey {
            transcript: Some(transcript),
            aggregated_key: aggregated_key.into(),
        })
    }

    fn compute_factor(transcript: &Transcript, X_i: &VerificationKey) -> Scalar {
        // a_i = H(<L>, X_i). Components of <L> have already been fed to transcript.
        let mut a_i_transcript = transcript.clone();
        a_i_transcript.commit_point(b"X_i", X_i.as_compressed());
        a_i_transcript.challenge_scalar(b"a_i")
    }

    /// Returns `a_i` factor for component key in aggregated key.
    pub fn factor_for_key(&self, X_i: &VerificationKey) -> Scalar {
        match &self.transcript {
            Some(t) => Multikey::compute_factor(&t, X_i),
            None => Scalar::one(),
        }
    }

    /// Returns VerificationKey representation of aggregated key.
    pub fn aggregated_key(&self) -> VerificationKey {
        self.aggregated_key
    }
}

/// Verification key (aka "pubkey") is a wrapper type around a Ristretto point and it's compressed variation
/// that lets the verifier check the validity of a signature.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct VerificationKey {
    point: RistrettoPoint,
    precompressed: CompressedRistretto,
}

impl VerificationKey {
    /// Constructs a VerificationKey from a private key.
    pub fn from_secret(privkey: &Scalar) -> Self {
        Self::from_secret_uncompressed(privkey).into()
    }

    /// Constructs an uncompressed VerificationKey point from a private key.
    pub(crate) fn from_secret_uncompressed(privkey: &Scalar) -> RistrettoPoint {
        (privkey * RISTRETTO_BASEPOINT_POINT)
    }

    /// Creates new key from a compressed form,remembers the compressed point.
    pub fn from_compressed(p: CompressedRistretto) -> Option<Self> {
        Some(VerificationKey {
            point: p.decompress()?,
            precompressed: p,
        })
    }

    /// Converts the Verification key to a compressed point
    pub fn into_compressed(self) -> CompressedRistretto {
        self.precompressed
    }

    /// Converts the Verification key to a ristretto point
    pub fn into_point(self) -> RistrettoPoint {
        self.point
    }

    /// Returns a reference to the compressed ristretto point
    pub fn as_compressed(&self) -> &CompressedRistretto {
        &self.precompressed
    }
}

impl From<RistrettoPoint> for VerificationKey {
    fn from(p: RistrettoPoint) -> Self {
        VerificationKey {
            point: p,
            precompressed: p.compress(),
        }
    }
}

impl Default for VerificationKey {
    fn default() -> Self {
        VerificationKey(CompressedRistretto::default())
    }
}