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

        let pieces = bytes.split_at(32);
        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&pieces.0[..]);
        let scalar = match Scalar::from_canonical_bytes(scalar_bytes) {
            Some(x) => x,
            None => return None,
        };
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&pieces.1[..]);
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

        let pieces = bytes.split_at(32);
        let precompressed_pubkey = CompressedRistretto::from_slice(&pieces.0[..]);
        let mut dk = [0u8; 32];
        dk.copy_from_slice(&pieces.1[..]);

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
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    #[test]
    fn random_xprv_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);

        // the following are hard-coded based on the previous seed
        let expected_dk = [
            159, 7, 231, 190, 85, 81, 56, 122, 152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41,
            160, 72, 227, 101, 105, 18, 198, 83, 62, 50, 238, 122, 237,
        ];
        let expected_scalar = Scalar::from_bits([
            74, 83, 195, 251, 188, 89, 151, 14, 229, 248, 90, 248, 19, 135, 93, 255, 193, 58, 144,
            74, 46, 83, 174, 126, 101, 250, 13, 234, 110, 98, 201, 1,
        ]);

        assert_eq!(expected_dk, xprv.dk);
        assert_eq!(expected_scalar, xprv.scalar);
    }

    #[test]
    fn serialize_xprv_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xprv_bytes = xprv.to_bytes();

        // hardcoded, but happens to be expected_scalar concatenated with expected_dk
        let expected_bytes = [
            74, 83, 195, 251, 188, 89, 151, 14, 229, 248, 90, 248, 19, 135, 93, 255, 193, 58, 144,
            74, 46, 83, 174, 126, 101, 250, 13, 234, 110, 98, 201, 1, 159, 7, 231, 190, 85, 81, 56,
            122, 152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227, 101, 105, 18, 198,
            83, 62, 50, 238, 122, 237,
        ];
        assert_eq!(&xprv_bytes[..], &expected_bytes[..]);
    }

    #[test]
    fn deserialize_xprv_test() {
        let xprv_bytes = [
            74, 83, 195, 251, 188, 89, 151, 14, 229, 248, 90, 248, 19, 135, 93, 255, 193, 58, 144,
            74, 46, 83, 174, 126, 101, 250, 13, 234, 110, 98, 201, 1, 159, 7, 231, 190, 85, 81, 56,
            122, 152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227, 101, 105, 18, 198,
            83, 62, 50, 238, 122, 237,
        ];

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

        // the following are hard-coded based on the previous seed
        let expected_dk = [
            159, 7, 231, 190, 85, 81, 56, 122, 152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41,
            160, 72, 227, 101, 105, 18, 198, 83, 62, 50, 238, 122, 237,
        ];
        let expected_compressed_point = CompressedRistretto::from_slice(&[
            156, 102, 163, 57, 200, 52, 79, 146, 47, 195, 32, 108, 181, 218, 232, 20, 165, 148,
            192, 23, 125, 211, 35, 92, 37, 77, 156, 64, 154, 101, 184, 8,
        ]);
        let expected_point = expected_compressed_point.decompress().unwrap();

        assert_eq!(xpub.dk, expected_dk);
        assert_eq!(xpub.point, expected_point);
        assert_eq!(xpub.precompressed_pubkey, expected_compressed_point);
    }

    #[test]
    fn serialize_xpub_test() {
        let seed = [0u8; 32];
        let mut rng = ChaChaRng::from_seed(seed);
        let xprv = Xprv::random(&mut rng);
        let xpub = xprv.to_xpub();

        let xpub_bytes = xpub.to_bytes();

        // hardcoded, but happens to be expected_scalar concatenated with expected_compressed_point
        let expected_bytes = [
            156, 102, 163, 57, 200, 52, 79, 146, 47, 195, 32, 108, 181, 218, 232, 20, 165, 148,
            192, 23, 125, 211, 35, 92, 37, 77, 156, 64, 154, 101, 184, 8, 159, 7, 231, 190, 85, 81,
            56, 122, 152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227, 101, 105, 18,
            198, 83, 62, 50, 238, 122, 237,
        ];
        assert_eq!(&xpub_bytes[..], &expected_bytes[..]);
    }

    #[test]
    fn deserialize_xpub_test() {
        let xpub_bytes = [
            156, 102, 163, 57, 200, 52, 79, 146, 47, 195, 32, 108, 181, 218, 232, 20, 165, 148,
            192, 23, 125, 211, 35, 92, 37, 77, 156, 64, 154, 101, 184, 8, 159, 7, 231, 190, 85, 81,
            56, 122, 152, 186, 151, 124, 115, 45, 8, 13, 203, 15, 41, 160, 72, 227, 101, 105, 18,
            198, 83, 62, 50, 238, 122, 237,
        ];
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

        // the following are hard-coded based on the previous seed
        let expected_dk = [
            54, 228, 53, 234, 188, 42, 86, 46, 242, 40, 184, 43, 57, 159, 189, 0, 75, 44, 198, 65,
            3, 49, 63, 166, 115, 189, 31, 202, 9, 113, 245, 157,
        ];
        let expected_compressed_point = CompressedRistretto::from_slice(&[
            116, 20, 192, 197, 35, 140, 34, 119, 49, 139, 163, 229, 31, 198, 251, 142, 131, 106,
            45, 155, 76, 4, 80, 143, 147, 205, 90, 69, 84, 34, 34, 27,
        ]);
        let expected_point = expected_compressed_point.decompress().unwrap();

        assert_eq!(xpub.dk, expected_dk);
        assert_eq!(xpub.point, expected_point);
        assert_eq!(xpub.precompressed_pubkey, expected_compressed_point);
    }
}
