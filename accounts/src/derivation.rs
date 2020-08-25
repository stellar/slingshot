use curve25519_dalek::constants::RISTRETTO_BASEPOINT_TABLE;
use curve25519_dalek::scalar::Scalar;
use keytree::{Xprv, Xpub};
use merlin::Transcript;
use musig::VerificationKey;
use zkvm::{ClearValue, TranscriptProtocol};

use super::Address;
use super::{Receiver, ReceiverWitness};

/// Extension trait for Xprv to derive keys based on sequence number.
pub trait XprvDerivation {
    /// Derives a key for a given sequence number.
    fn key_at_sequence(&self, sequence: u64) -> Scalar;
}

impl XprvDerivation for Xprv {
    fn key_at_sequence(&self, sequence: u64) -> Scalar {
        self.derive_key(|t| t.append_u64(b"sequence", sequence))
    }
}

/// Extension trait for Xprv to derive keys based on sequence number.
pub trait XpubDerivation {
    /// Derives a key for a given sequence number.
    fn key_at_sequence(&self, sequence: u64) -> VerificationKey;

    /// Derives an Address for a given sequence number.
    fn address_at_sequence(&self, label: String, sequence: u64) -> Address;

    /// Creates a new receiver for the given sequence number and value
    fn receiver_at_sequence(&self, sequence: u64, value: ClearValue) -> ReceiverWitness;

    /// Derives blinding factors for the given value and sequence number.
    /// Q: Why deterministic derivation?
    /// A: Blinding factors are high-entropy, so loss of such data is fatal.
    ///    While loss of low-entropy metadata such as qty and flavor is recoverable
    ///    from multiple other systems (analytics, counter-parties), or even by bruteforce search.
    fn value_blinding_factors(&self, sequence: u64, value: &ClearValue) -> (Scalar, Scalar);
}

impl XpubDerivation for Xpub {
    fn key_at_sequence(&self, sequence: u64) -> VerificationKey {
        self.derive_key(|t| t.append_u64(b"sequence", sequence))
    }

    fn address_at_sequence(&self, label: String, sequence: u64) -> Address {
        let ctrl_key = self.key_at_sequence(sequence);
        // Note: we derive encryption privkey from the xpub public key, effectively binding it
        // to the secrecy of only the derivation key of xpub.
        // This allows us to decrypt transaction using xpub only,
        // w/o having access to a more sensitive xprv needed to move the funds.
        let mut t = Transcript::new(b"ZkVM.accounts.encryption-key");
        t.append_message(b"xpub", &self.to_bytes());
        t.append_message(b"label", label.as_bytes());
        t.append_u64(b"sequence", sequence);
        let enc_key = t.challenge_scalar(b"key");

        Address::new(
            label,
            ctrl_key.into_point(),
            &enc_key * &RISTRETTO_BASEPOINT_TABLE,
        )
    }

    fn receiver_at_sequence(&self, sequence: u64, value: ClearValue) -> ReceiverWitness {
        let key = self.key_at_sequence(sequence);
        let (qty_blinding, flv_blinding) = self.value_blinding_factors(sequence, &value);

        ReceiverWitness {
            sequence,
            receiver: Receiver {
                opaque_predicate: key.into_point(),
                value,
                qty_blinding,
                flv_blinding,
            },
        }
    }

    fn value_blinding_factors(&self, sequence: u64, value: &ClearValue) -> (Scalar, Scalar) {
        // Blinding factors are deterministically derived in order to avoid
        // having to backup secret material.
        // It can be always re-created from the single root xpub.
        let mut t = Transcript::new(b"ZkVM.accounts.blinding");
        t.append_message(b"xpub", &self.to_bytes());
        t.append_u64(b"sequence", sequence);
        t.append_u64(b"qty", value.qty);
        t.append_message(b"flv", value.flv.as_bytes());
        let q = t.challenge_scalar(b"qty_blinding");
        let f = t.challenge_scalar(b"flv_blinding");
        (q, f)
    }
}
