#![deny(missing_docs)]
//! Implementation of the key tree protocol, a key blinding scheme for deriving hierarchies of public keys.

use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, RngCore};

/// Xprv represents an extended private key.
pub struct Xprv {
    scalar: Scalar,
    dk: [u8; 32],
}

impl Xprv {
    /// Returns a new Xprv, generated using the provided random number generator `rng`.
    pub fn random<T: RngCore + CryptoRng>(mut rng: T) -> Self {
        let scalar = Scalar::random(&mut rng);
        let mut dk = [0u8; 32];
        rng.fill_bytes(&mut dk);
        Xprv { scalar, dk }
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
}
