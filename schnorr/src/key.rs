use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

/// Verification key (aka "pubkey") is a wrapper type around a Ristretto point
/// that lets the verifier to check the signature.
/// `VerificationKey` stores both compressed and decompressed point, so that
/// (1) compression is not performed again when key is appended to the Transcript;
/// (2) decompression failures are handled during decoding and allow key derivation without errors.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
#[serde(from="RistrettoPoint", into="RistrettoPoint")]
pub struct VerificationKey {
    point: RistrettoPoint,
    precompressed: CompressedRistretto,
}

impl VerificationKey {
    /// Constructs a VerificationKey from a private key.
    pub fn from_secret(privkey: &Scalar) -> Self {
        (privkey * RISTRETTO_BASEPOINT_POINT).into()
    }

    /// Creates new key from a compressed form,remembers the compressed point.
    pub fn from_compressed(p: CompressedRistretto) -> Option<Self> {
        Some(VerificationKey {
            point: p.decompress()?,
            precompressed: p,
        })
    }

    /// Converts the Verification key to a compressed point
    pub fn into_compressed(self) -> CompressedRistretto {
        self.precompressed
    }

    /// Converts the Verification key to a ristretto point
    pub fn into_point(self) -> RistrettoPoint {
        self.point
    }

    /// Returns a reference to the compressed ristretto point
    pub fn as_compressed(&self) -> &CompressedRistretto {
        &self.precompressed
    }

    /// Returns a reference to the compressed ristretto point
    pub fn as_point(&self) -> &RistrettoPoint {
        &self.point
    }

    /// Returns the view into byte representation of the verification key
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.as_compressed().as_bytes()
    }

    /// Returns the byte representation of the verification key
    pub fn to_bytes(&self) -> [u8; 32] {
        self.as_compressed().to_bytes()
    }
}

impl From<RistrettoPoint> for VerificationKey {
    fn from(p: RistrettoPoint) -> Self {
        VerificationKey {
            point: p,
            precompressed: p.compress(),
        }
    }
}

impl Into<RistrettoPoint> for VerificationKey {
    fn into(self) -> RistrettoPoint {
        self.into_point()
    }
}
