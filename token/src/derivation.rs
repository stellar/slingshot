use curve25519_dalek::scalar::Scalar;
use keytree::{Xprv, Xpub};
use merlin::Transcript;
use musig::VerificationKey;
use zkvm::TranscriptProtocol;

use super::Token;

/// Extension trait for Xprv to derive issuing keys based on the asset alias.
pub trait XprvDerivation {
    /// Derives a key for a given asset alias.
    fn issuing_key(&self, alias: &str) -> Scalar;
}

impl XprvDerivation for Xprv {
    fn issuing_key(&self, alias: &str) -> Scalar {
        self.derive_key(|t| t.append_message(b"token.alias", alias.as_bytes()))
    }
}

/// Extension trait for Xprv to derive keys based on sequence number.
pub trait XpubDerivation {
    /// Derives a key for a given asset alias.
    fn issuing_key(&self, alias: &str) -> VerificationKey;

    /// Derives an Address for a given sequence number.
    fn derive_token(&self, alias: &str) -> Token;

    /// Derives blinding factors for the given value and sequence number.
    /// Q: Why deterministic derivation?
    /// A: Blinding factors are high-entropy, so loss of such data is fatal.
    ///    While loss of low-entropy metadata such as qty and flavor is recoverable
    ///    from multiple other systems (analytics, counter-parties), or even by bruteforce search.
    fn value_blinding_factor(&self, alias: &str, qty: u64) -> Scalar;
}

impl XpubDerivation for Xpub {
    fn issuing_key(&self, alias: &str) -> VerificationKey {
        self.derive_key(|t| t.append_message(b"token.alias", alias.as_bytes()))
    }

    fn derive_token(&self, alias: &str) -> Token {
        let key = self.issuing_key(alias);
        Token::new(
            zkvm::Predicate::Opaque(*key.as_point()),
            alias.as_bytes().to_vec(),
        )
    }

    fn value_blinding_factor(&self, alias: &str, qty: u64) -> Scalar {
        // Blinding factors are deterministically derived in order to avoid
        // having to backup secret material.
        // It can be always re-created from the single root xpub.
        let mut t = Transcript::new(b"ZkVM.token.blinding");
        t.append_message(b"xpub", &self.to_bytes());
        t.append_message(b"alias", alias.as_bytes());
        t.append_u64(b"qty", qty);
        t.challenge_scalar(b"qty_blinding")
    }
}
