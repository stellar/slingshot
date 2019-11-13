//! Defines a `TranscriptProtocol` trait for using a Merlin transcript.
use merlin::Transcript;
use starsig::TranscriptProtocol as StarsigTranscriptProtocol;

/// Extension trait to the Merlin transcript API that allows committing scalars and points and
/// generating challenges as scalars.
pub trait TranscriptProtocol: StarsigTranscriptProtocol {
    /// Commit a domain separator for a multi-message signature protocol with `n` keys.
    fn musig_multimessage_domain_sep(&mut self, n: usize);
}

impl TranscriptProtocol for Transcript {
    fn musig_multimessage_domain_sep(&mut self, n: usize) {
        self.append_message(b"dom-sep", b"musig-multimessage v1");
        self.append_u64(b"n", n as u64);
    }
}
