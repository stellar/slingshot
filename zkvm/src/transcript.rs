//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// Extension trait to the Merlin transcript API that allows committing scalars and points and
/// generating challenges as scalars.
pub trait TranscriptProtocol {
    /// Commit a `scalar` with the given `label`.
    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    /// Commit a `point` with the given `label`.
    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar) {
        self.commit_bytes(label, scalar.as_bytes());
    }

    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
        self.commit_bytes(label, point.as_bytes());
    }

    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
        let mut buf = [0u8; 64];
        self.challenge_bytes(label, &mut buf);

        Scalar::from_bytes_mod_order_wide(&buf)
    }
}
