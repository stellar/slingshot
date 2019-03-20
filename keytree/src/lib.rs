#![deny(missing_docs)]
//! Implementation of the key tree protocol, a key blinding scheme for deriving hierarchies of public keys.

use crate::transcript::TranscriptProtocol;
use curve25519_dalek::constants;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::{CryptoRng, RngCore};

mod transcript;

/// Xprv represents an extended private key.
pub struct Xprv {
    scalar: Scalar,
    dk: [u8; 32],
    precompressed_pubkey: CompressedRistretto,
}

/// Xpub represents an extended public key.
pub struct Xpub {
    point: RistrettoPoint,
    dk: [u8; 32],
    precompressed_pubkey: CompressedRistretto,
}

impl Xprv {
    /// Returns a new Xprv, generated using the provided random number generator `rng`.
    pub fn random<T: RngCore + CryptoRng>(mut rng: T) -> Self {
        let scalar = Scalar::random(&mut rng);
        let mut dk = [0u8; 32];
        rng.fill_bytes(&mut dk);

        let precompressed_pubkey = (scalar * &constants::RISTRETTO_BASEPOINT_POINT).compress();

        Xprv {
            scalar,
            dk,
            precompressed_pubkey,
        }
    }

    /// Returns a new Xpub, generated from the provided Xprv.
    pub fn to_xpub(&self) -> Xpub {
        let point = self.scalar * &constants::RISTRETTO_BASEPOINT_POINT;
        Xpub {
            point: point,
            dk: self.dk,
            precompressed_pubkey: self.precompressed_pubkey,
        }
    }

    /// Serializes this Xprv to a sequence of bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&self.scalar.to_bytes());
        buf[32..].copy_from_slice(&self.dk);
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
        let precompressed_pubkey = (scalar * &constants::RISTRETTO_BASEPOINT_POINT).compress();

        return Some(Xprv {
            scalar,
            dk,
            precompressed_pubkey,
        });
    }
}

impl Xpub {
    /// Returns a intermediate child pubkey. Users must provide customize, in order to separate
    /// sibling keys from one another through unique derivation paths.
    pub fn derive_intermediate_key(&self, customize: impl FnOnce(&mut Transcript)) -> Xpub {
        let mut t = Transcript::new(b"Keytree.derivation");
        t.commit_bytes(b"pt", self.precompressed_pubkey.as_bytes());
        t.commit_bytes(b"dk", &self.dk);

        // change the derivation path for this key
        customize(&mut t);

        // squeeze a challenge scalar
        let f = t.challenge_scalar(b"f.intermediate");

        // squeeze a new derivation key
        let mut child_dk = [0u8; 32];
        t.challenge_bytes(b"dk", &mut child_dk);

        let child_point = self.point + (f * &constants::RISTRETTO_BASEPOINT_POINT);

        Xpub {
            point: child_point,
            dk: child_dk,
            precompressed_pubkey: child_point.compress(),
        }
    }

    /// Serializes this Xpub to a sequence of bytes.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.precompressed_pubkey.as_bytes());
        buf[32..].copy_from_slice(&self.dk);
        buf
    }

    /// Decodes an Xpub from a 64-byte array, and fails if the provided array is not
    /// exactly 64 bytes, or if the compressed point fails to decompress.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }

        let precompressed_pubkey = CompressedRistretto::from_slice(&bytes[..32]);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&bytes[32..]);

        let point = match precompressed_pubkey.decompress() {
            Some(p) => p,
            None => return None,
        };

        Some(Xpub {
            point,
            dk,
            precompressed_pubkey,
        })
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
            to_hex_32(xprv.dk),
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
        assert_eq!(
            hex::encode(xprv.scalar.as_bytes()),
            "4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c901"
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

        assert_eq!(xprv.dk, expected_xprv.dk);
        assert_eq!(xprv.scalar, expected_xprv.scalar);
    }

    #[test]
    fn random_xpub_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xpub = xprv.to_xpub();

        // hard-coded based on the previous seed
        let expected_compressed_point = CompressedRistretto::from_slice(
            &hex::decode("9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b808")
                .unwrap(),
        );
        let expected_point = expected_compressed_point.decompress().unwrap();

        assert_eq!(
            to_hex_32(xpub.dk),
            "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
        );
        assert_eq!(xpub.point, expected_point);
        assert_eq!(xpub.precompressed_pubkey, expected_compressed_point);
    }

    #[test]
    fn serialize_xpub_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xpub = xprv.to_xpub();

        // hardcoded, but happens to be expected_scalar concatenated with expected_compressed_point
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
        assert_eq!(xpub.point, expected_xpub.point);
        assert_eq!(
            xpub.precompressed_pubkey,
            expected_xpub.precompressed_pubkey
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

        // hard-coded based on the previous seed
        let expected_compressed_point = CompressedRistretto::from_slice(
            &hex::decode("7414c0c5238c2277318ba3e51fc6fb8e836a2d9b4c04508f93cd5a455422221b")
                .unwrap(),
        );
        let expected_point = expected_compressed_point.decompress().unwrap();

        assert_eq!(
            to_hex_32(xpub.dk),
            "36e435eabc2a562ef228b82b399fbd004b2cc64103313fa673bd1fca0971f59d"
        );
        assert_eq!(xpub.point, expected_point);
        assert_eq!(xpub.precompressed_pubkey, expected_compressed_point);
    }

    fn to_hex_32(input: [u8; 32])->String {
        return hex::encode(&input[..]);
    }

    fn to_hex_64(input: [u8; 64])->String {
        return hex::encode(&input[..]);
    }

}
