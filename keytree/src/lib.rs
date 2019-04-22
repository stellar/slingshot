#![deny(missing_docs)]
//! Implementation of the key tree protocol, a key blinding scheme for deriving hierarchies of public keys.

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use musig::VerificationKey;
use rand::{CryptoRng, RngCore};

mod transcript;

/// Xprv represents an extended private key.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct Xprv {
    scalar: Scalar,
    xpub: Xpub,
}

/// Xpub represents an extended public key.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug)]
pub struct Xpub {
    pubkey: VerificationKey,
    dk: [u8; 32],
}

/// Represents a derivation object for deriving private keys in a batch
pub struct PrivateDerivation<'a> {
    prf: Transcript,
    parent: &'a Xprv,
}

/// Represents a derivation object for deriving public keys in a batch
pub struct PublicDerivation<'a> {
    prf: Transcript,
    parent: &'a Xpub,
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

    /// Allows deriving multiple keys in a batch, by reusing common part of the PRF.
    pub fn batch_derivation<F, T>(&self, closure: F) -> T
    where
        F: FnOnce(PrivateDerivation) -> T,
    {
        closure(PrivateDerivation {
            prf: self.xpub.prepare_prf(),
            parent: self,
        })
    }
}

impl Xpub {
    /// Returns a intermediate child pubkey. Users must provide customize, in order to separate
    /// sibling keys from one another through unique derivation paths.
    pub fn derive_intermediate_key(&self, customize: impl FnOnce(&mut Transcript)) -> Xpub {
        let (xpub, _f) = self.derive_intermediate_helper(self.prepare_prf(), customize);
        xpub
    }

    /// Returns a leaf Xpub, which can safely be shared.
    /// Users must provide customize, in order to separate sibling keys from one another
    /// through unique derivation paths.
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

    /// Allows deriving multiple keys in a batch, by reusing common part of the PRF.
    pub fn batch_derivation<F, T>(&self, closure: F) -> T
    where
        F: FnOnce(PublicDerivation) -> T,
    {
        closure(PublicDerivation {
            prf: self.prepare_prf(),
            parent: self,
        })
    }

    fn prepare_prf(&self) -> Transcript {
        let mut t = Transcript::new(b"Keytree.derivation");
        t.commit_point(b"pt", self.pubkey.as_compressed());
        t.commit_bytes(b"dk", &self.dk);
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

impl<'a> PrivateDerivation<'a> {
    /// Returns an intermediate Xprv derived using a PRF customized with a user-provided closure.
    pub fn derive_intermediate_key(&'a self, customize: impl FnOnce(&mut Transcript)) -> Xprv {
        let (xpub, f) = self
            .parent
            .xpub
            .derive_intermediate_helper(self.prf.clone(), customize);
        Xprv {
            scalar: self.parent.scalar + f,
            xpub,
        }
    }

    /// Returns a leaf secret scalar derived using a PRF customized with a user-provided closure.
    pub fn derive_key(&self, customize: impl FnOnce(&mut Transcript)) -> Scalar {
        let f = self
            .parent
            .xpub
            .derive_leaf_helper(self.prf.clone(), customize);
        self.parent.scalar + f
    }
}

impl<'a> PublicDerivation<'a> {
    /// Returns an intermediate Xpub derived using a PRF customized with a user-provided closure.
    pub fn derive_intermediate_key(&self, customize: impl FnOnce(&mut Transcript)) -> Xpub {
        let (xpub, _f) = self
            .parent
            .derive_intermediate_helper(self.prf.clone(), customize);
        xpub
    }

    /// Returns a leaf VerificationKey derived using a PRF customized with a user-provided closure.
    pub fn derive_key(&self, customize: impl FnOnce(&mut Transcript)) -> VerificationKey {
        let f = self.parent.derive_leaf_helper(self.prf.clone(), customize);
        let child_point =
            self.parent.pubkey.as_point() + (&f * &constants::RISTRETTO_BASEPOINT_TABLE);
        child_point.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn random_xprv_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);

        // the following are hard-coded based on the previous seed
        assert_eq!(
            to_hex_32(xprv.xpub.dk),
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
        assert_eq!(
            hex::encode(xprv.scalar.as_bytes()),
            "4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c901"
        );
    }

    #[test]
    fn random_xprv_derivation_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng).derive_intermediate_key(|t| {
            t.commit_u64(b"account_id", 34);
        });

        assert_eq!(
            hex::encode(xprv.scalar.as_bytes()),
            "55d65740c47cff19c35c2787dbc0e207e901fbb311caa4d583da8efdc7088b03"
        );
        assert_eq!(
            to_hex_32(xprv.xpub.dk),
            "36e435eabc2a562ef228b82b399fbd004b2cc64103313fa673bd1fca0971f59d"
        );
        assert_eq!(
            to_hex_32(xprv.xpub.pubkey.as_compressed().to_bytes()),
            "7414c0c5238c2277318ba3e51fc6fb8e836a2d9b4c04508f93cd5a455422221b"
        );
    }

    #[test]
    fn random_xprv_leaf_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng).derive_key(|t| {
            t.commit_u64(b"invoice_id", 10034);
        });

        assert_eq!(
            hex::encode(xprv.as_bytes()),
            "a71e5435c3374eef60928c3bac1378dcbc91bc1d554e09242247a0861fd12c0c"
        );
    }

    #[test]
    fn serialize_xprv_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xprv_bytes = xprv.to_bytes();

        assert_eq!(
            to_hex_64(xprv_bytes),
            "4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c9019f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
    }

    #[test]
    fn deserialize_xprv_test() {
        let xprv_bytes = hex::decode("4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c9019f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed").unwrap();
        let xprv = Xprv::from_bytes(&xprv_bytes).unwrap();

        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let expected_xprv = Xprv::random(&mut rng);

        assert_eq!(xprv.xpub.dk, expected_xprv.xpub.dk);
        assert_eq!(xprv.scalar, expected_xprv.scalar);
    }

    #[test]
    fn random_xpub_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xpub = xprv.to_xpub();

        // hex strings are hard-coded based on the previous seed
        assert_eq!(
            to_hex_32(xpub.dk),
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
        assert_eq!(
            to_hex_32(xpub.pubkey.to_bytes()),
            "9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b808"
        );
    }

    #[test]
    fn serialize_xpub_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xpub = xprv.to_xpub();

        assert_eq!(
            to_hex_64(xpub.to_bytes()),
            "9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b8089f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
    }

    #[test]
    fn deserialize_xpub_test() {
        let xpub_bytes = hex::decode("9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b8089f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed").unwrap();
        let xpub = Xpub::from_bytes(&xpub_bytes).unwrap();

        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let expected_xprv = Xprv::random(&mut rng);
        let expected_xpub = expected_xprv.to_xpub();

        assert_eq!(xpub.dk, expected_xpub.dk);
        assert_eq!(xpub.pubkey, expected_xpub.pubkey);
        assert_eq!(
            xpub.pubkey.as_compressed(),
            expected_xpub.pubkey.as_compressed()
        );
    }

    #[test]
    fn random_xpub_derivation_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xpub = xprv.to_xpub().derive_intermediate_key(|t| {
            t.commit_u64(b"account_id", 34);
        });

        assert_eq!(
            to_hex_32(xpub.dk),
            "36e435eabc2a562ef228b82b399fbd004b2cc64103313fa673bd1fca0971f59d"
        );
        assert_eq!(
            to_hex_32(xpub.pubkey.to_bytes()),
            "7414c0c5238c2277318ba3e51fc6fb8e836a2d9b4c04508f93cd5a455422221b"
        );
    }

    #[test]
    fn random_xpub_leaf_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let pubkey = xprv.to_xpub().derive_key(|t| {
            t.commit_u64(b"invoice_id", 10034);
        });

        assert_eq!(
            hex::encode(pubkey.as_bytes()),
            "a202e8a0b6fb7123bf1e2aaaf90ed9c3c55f7d1975ed4b63b4417e5d7397c048"
        );
    }

    fn to_hex_32(input: [u8; 32]) -> String {
        return hex::encode(&input[..]);
    }

    fn to_hex_64(input: [u8; 64]) -> String {
        return hex::encode(&input[..]);
    }

}
