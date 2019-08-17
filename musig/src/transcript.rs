//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.
use merlin::Transcript;
use schnorr::TranscriptProtocol as SchnorrTranscriptProtocol;

/// Extension trait to the Merlin transcript API that allows committing scalars and points and
/// generating challenges as scalars.
pub trait TranscriptProtocol: SchnorrTranscriptProtocol {
    /// Commit a domain separator for a multi-message signature protocol with `n` keys.
    fn schnorr_multisig_domain_sep(&mut self, n: usize);
}

impl TranscriptProtocol for Transcript {
    fn schnorr_multisig_domain_sep(&mut self, n: usize) {
        self.append_message(b"dom-sep", b"schnorr-multi-signature v1");
        self.append_u64(b"n", n as u64);
    }
}
