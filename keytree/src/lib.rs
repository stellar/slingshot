#![deny(missing_docs)]
//! Implementation of the key tree protocol, a key blinding scheme for deriving hierarchies of public keys.

use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::VerificationKey;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

use crate::transcript::TranscriptProtocol;

mod transcript;

#[cfg(test)]
mod tests;

/// Xprv represents an extended private key.
/// TBD: change serialization to encode a single 64-byte blob, with hex for human-readable formats
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
pub struct Xprv {
    scalar: Scalar,
    xpub: Xpub,
}

/// Xpub represents an extended public key.
/// TBD: change serialization to encode a single 64-byte blob, with hex for human-readable formats
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
pub struct Xpub {
    pubkey: VerificationKey,
    dk: [u8; 32],
}

impl Xprv {
    /// Returns a new Xprv, generated using the provided random number generator `rng`.
    pub fn random<T: RngCore + CryptoRng>(mut rng: T) -> Self {
        let scalar = Scalar::random(&mut rng);
        let mut dk = [0u8; 32];
        rng.fill_bytes(&mut dk);

        let pubkey = VerificationKey::from_secret(&scalar);

        Xprv {
            scalar,
            xpub: Xpub { pubkey, dk },
        }
    }

    /// Returns a new Xpub, generated from the provided Xprv.
    pub fn as_xpub(&self) -> &Xpub {
        &self.xpub
    }

    /// Converts Xprv into Xpub without consuming self.
    pub fn to_xpub(&self) -> Xpub {
        self.xpub
    }

    /// Converts Xprv into Xpub.
    pub fn into_xpub(self) -> Xpub {
        self.xpub
    }

    /// Returns an intermediate Xprv derived using a PRF customized with a user-provided closure.
    pub fn derive_intermediate_key(&self, customize: impl FnOnce(&mut Transcript)) -> Xprv {
        let (child_xpub, f) = self
            .xpub
            .derive_intermediate_helper(self.xpub.prepare_prf(), customize);

        Xprv {
            scalar: self.scalar + f,
            xpub: child_xpub,
        }
    }

    /// Returns a leaf secret scalar derived using a PRF customized with a user-provided closure.
    pub fn derive_key(&self, customize: impl FnOnce(&mut Transcript)) -> Scalar {
        let f = self
            .xpub
            .derive_leaf_helper(self.xpub.prepare_prf(), customize);
        self.scalar + f
    }

    /// Serializes this Xprv to a sequence of bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.scalar.to_bytes());
        buf[32..].copy_from_slice(&self.xpub.dk);
        buf
    }

    /// Decodes an Xprv from a 64-byte array, and fails if the provided array is not
    /// exactly 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&bytes[..32]);
        let scalar = match Scalar::from_canonical_bytes(scalar_bytes) {
            Some(x) => x,
            None => return None,
        };
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&bytes[32..]);

        return Some(Xprv {
            scalar,
            xpub: Xpub {
                pubkey: VerificationKey::from_secret(&scalar),
                dk,
            },
        });
    }
}

impl Xpub {
    /// Returns an intermediate Xpub derived using a PRF customized with a user-provided closure.
    pub fn derive_intermediate_key(&self, customize: impl FnOnce(&mut Transcript)) -> Xpub {
        let (xpub, _f) = self.derive_intermediate_helper(self.prepare_prf(), customize);
        xpub
    }

    /// Returns a leaf `VerificationKey` derived using a PRF customized with a user-provided closure.
    pub fn derive_key(&self, customize: impl FnOnce(&mut Transcript)) -> VerificationKey {
        let f = self.derive_leaf_helper(self.prepare_prf(), customize);
        (self.pubkey.as_point() + (&f * &constants::RISTRETTO_BASEPOINT_TABLE)).into()
    }

    /// Serializes this Xpub to a sequence of bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.pubkey.as_compressed().as_bytes());
        buf[32..].copy_from_slice(&self.dk);
        buf
    }

    /// Decodes an Xpub from a 64-byte array, and fails if the provided array is not
    /// exactly 64 bytes, or if the compressed point fails to decompress.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }

        let compressed_pubkey = CompressedRistretto::from_slice(&bytes[..32]);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&bytes[32..]);

        let pubkey = match VerificationKey::from_compressed(compressed_pubkey) {
            Some(p) => p,
            None => return None,
        };

        Some(Xpub { pubkey, dk })
    }

    fn prepare_prf(&self) -> Transcript {
        let mut t = Transcript::new(b"Keytree.derivation");
        t.commit_point(b"pt", self.pubkey.as_compressed());
        t.append_message(b"dk", &self.dk);
        t
    }

    fn derive_intermediate_helper(
        &self,
        mut prf: Transcript,
        customize: impl FnOnce(&mut Transcript),
    ) -> (Xpub, Scalar) {
        // change the derivation path for this key
        customize(&mut prf);

        // squeeze a challenge scalar
        let f = prf.challenge_scalar(b"f.intermediate");

        // squeeze a new derivation key
        let mut child_dk = [0u8; 32];
        prf.challenge_bytes(b"dk", &mut child_dk);

        let child_point = self.pubkey.as_point() + (&f * &constants::RISTRETTO_BASEPOINT_TABLE);

        let xpub = Xpub {
            pubkey: child_point.into(),
            dk: child_dk,
        };

        (xpub, f)
    }

    fn derive_leaf_helper(
        &self,
        mut prf: Transcript,
        customize: impl FnOnce(&mut Transcript),
    ) -> Scalar {
        customize(&mut prf);
        prf.challenge_scalar(b"f.leaf")
    }
}
