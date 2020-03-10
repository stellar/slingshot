//! Short ID implementation.
//! A 6-byte transaction ID, specified for a given nonce and a context (u64-sized slice).
//!
//! 1. Initialize [SipHash-2-4](https://131002.net/siphash/) with k0 set to nonce, k1 set to the little-endian u64 read from the context string.
//! 2. Feed transaction ID as an input to SipHash.
//! 3. Read u64 output, drop two most significant bytes.
//!
//! Based on [BIP-152](https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki).

use core::hash::Hasher;
use serde::{Deserialize, Serialize};
use siphasher::sip::SipHasher;

/// Short ID definition
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ShortID {
    inner: u64,
}

/// Hasher that produces `ID`s
#[derive(Copy, Clone, Debug)]
pub struct Transform {
    sip: SipHasher,
}

impl ShortID {
    /// Reads Short ID from a slice of bytes.
    /// Returns None if the slice is shorter than 6 bytes.
    pub fn from_bytes(slice: &[u8]) -> Option<Self> {
        if slice.len() == 6 {
            Some(ShortID {
                inner: slice[0] as u64
                    + ((slice[1] as u64) << 8)
                    + ((slice[2] as u64) << 16)
                    + ((slice[3] as u64) << 24)
                    + ((slice[4] as u64) << 32)
                    + ((slice[5] as u64) << 40),
            })
        } else {
            None
        }
    }

    pub fn to_bytes(self) -> [u8; 6] {
        [
            (self.inner & 0xff) as u8,
            ((self.inner >> 8) & 0xff) as u8,
            ((self.inner >> 16) & 0xff) as u8,
            ((self.inner >> 24) & 0xff) as u8,
            ((self.inner >> 32) & 0xff) as u8,
            ((self.inner >> 40) & 0xff) as u8,
        ]
    }

    fn from_u64(int: u64) -> Self {
        ShortID {
            inner: int & 0xffff_ffff_ffff,
        }
    }
}

impl Transform {
    /// Creates a new Short ID hasher from a nonce and a context string.
    pub fn new(nonce: u64, context: &[u8]) -> Self {
        Self {
            sip: SipHasher::new_with_keys(nonce, read_le64(context)),
        }
    }

    /// Transforms a long identifier into a `ShortID`.
    pub fn apply(&self, longid: impl AsRef<[u8]>) -> ShortID {
        let mut h = self.sip.clone();
        h.write(longid.as_ref());
        ShortID::from_u64(h.finish())
    }
}

/// Reads little-endian u64 from a slice.
/// Treats missing higher-order bits as zeroes.
fn read_le64(slice: &[u8]) -> u64 {
    slice
        .iter()
        .enumerate()
        .fold(0u64, |r, (i, b)| r + ((*b as u64) << (i * 8)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_proofs() {
        let t = Transform::new(0u64, &[42u8]);
        let id_foo = t.apply(b"foo");
        let id_bar = t.apply(b"bar");
        assert_eq!(id_foo.to_bytes(), [0x50, 0x74, 0x5c, 0xd8, 0x7d, 0xd7]);
        assert_eq!(id_bar.to_bytes(), [0x5a, 0x48, 0x9e, 0xb8, 0x6e, 0x61]);
        let id_foo2 = ShortID::from_bytes(&[0x50, 0x74, 0x5c, 0xd8, 0x7d, 0xd7]).unwrap();
        assert_eq!(id_foo2.to_bytes(), [0x50, 0x74, 0x5c, 0xd8, 0x7d, 0xd7]);
        let id_foo3 = ShortID::from_u64(0xdead_d77d_d85c_7450); // top 2 bytes are zeroed.
        assert_eq!(id_foo3.to_bytes(), [0x50, 0x74, 0x5c, 0xd8, 0x7d, 0xd7]);
    }
}
