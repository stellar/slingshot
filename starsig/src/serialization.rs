use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use serde::{de::Deserializer, de::Visitor, ser::Serializer, Deserialize, Serialize};

use super::Signature;
use super::StarsigError;

impl Signature {
    /// Decodes a signature from a 64-byte slice.
    pub fn from_bytes(sig: impl AsRefExt) -> Result<Self, StarsigError> {
        let sig = sig.as_ref_ext();
        if sig.len() != 64 {
            return Err(StarsigError::InvalidSignature);
        }
        let mut Rbuf = [0u8; 32];
        let mut sbuf = [0u8; 32];
        Rbuf[..].copy_from_slice(&sig[..32]);
        sbuf[..].copy_from_slice(&sig[32..]);
        Ok(Signature {
            R: CompressedRistretto(Rbuf),
            s: Scalar::from_canonical_bytes(sbuf).ok_or(StarsigError::InvalidSignature)?,
        })
    }

    /// Encodes the signature as a 64-byte array.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(self.R.as_bytes());
        buf[32..].copy_from_slice(self.s.as_bytes());
        buf
    }
}

/// Same as `AsRef<[u8]>`, but extended to 64-byte array.
pub trait AsRefExt {
    /// Returns a slice
    fn as_ref_ext(&self) -> &[u8];
}

impl AsRefExt for [u8] {
    fn as_ref_ext(&self) -> &[u8] {
        self
    }
}

impl<'a> AsRefExt for &'a [u8] {
    fn as_ref_ext(&self) -> &[u8] {
        self
    }
}

impl AsRefExt for [u8; 64] {
    fn as_ref_ext(&self) -> &[u8] {
        &self[..]
    }
}

// TBD: serialize in hex in case of a human-readable serializer
impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.to_bytes()[..])
    }
}
impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> Visitor<'de> for SigVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid schnorr signature")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Signature, E>
            where
                E: serde::de::Error,
            {
                Signature::from_bytes(v).map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_bytes(SigVisitor)
    }
}
