//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.

use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

/// Extension trait to the Merlin transcript API that allows committing scalars and points and
/// generating challenges as scalars.
pub trait TranscriptProtocol {
    /// Commit a domain separator for a single-message signature protocol.
    fn schnorr_sig_domain_sep(&mut self);
    /// Commit a domain separator for a multi-message signature protocol with `n` keys.
    fn schnorr_multisig_domain_sep(&mut self, n: usize);
    /// Commit a `scalar` with the given `label`.
    fn commit_scalar(&mut self, label: &'static [u8], scalar: &Scalar);
    /// Commit a `point` with the given `label`.
    fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
    /// Compute a `label`ed challenge variable.
    fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
}

impl TranscriptProtocol for Transcript {
    fn schnorr_sig_domain_sep(&mut self) {
        self.commit_bytes(b"dom-sep", b"schnorr-signature v1");
    }
    fn schnorr_multisig_domain_sep(&mut self, n: usize) {
        self.commit_bytes(b"dom-sep", b"schnorr-multi-signature v1");
        self.commit_u64(b"n", n as u64);
    }
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
