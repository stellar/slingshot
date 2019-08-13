use rand::SeedableRng;
use rand_chacha::ChaChaRng;
use curve25519_dalek::scalar::Scalar;

use keytree::Xprv;

/// Deterministically creates an Xprv from an alias.
/// Only first 32 bytes of the alias contribute as entropy.
pub fn xprv_from_string(string: &String) -> Xprv {
    let mut seed = [0u8; 32];
    let bytes = string.as_bytes();
    let n = std::cmp::min(32, bytes.len());
    seed[..n].copy_from_slice(&bytes[..n]);

    Xprv::random(&mut ChaChaRng::from_seed(seed))
}

/// Deterministically creates a privkey from an alias.
/// Only first 32 bytes of the alias contribute as entropy.
pub fn scalar_from_string(string: &String) -> Scalar {
    let mut seed = [0u8; 32];
    let bytes = string.as_bytes();
    let n = std::cmp::min(32, bytes.len());
    seed[..n].copy_from_slice(&bytes[..n]);

    Scalar::random(&mut ChaChaRng::from_seed(seed))
}