use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

/// Signing key (aka "privkey") is a type alias for the scalar in Ristretto255 group.
pub type SigningKey = Scalar;

/// Verification key (aka "pubkey") is a wrapper type around a Ristretto point
/// that lets the verifier to check the signature.
#[derive(Copy, Clone, PartialEq, Eq, Default, Debug, Serialize, Deserialize)]
#[serde(from = "CompressedRistretto", into = "CompressedRistretto")]
pub struct VerificationKey {
    point: CompressedRistretto,
}

impl VerificationKey {
    /// Constructs a VerificationKey from a private key.
    pub fn from_secret(privkey: &Scalar) -> Self {
        Self::from_secret_decompressed(privkey).into()
    }

    /// Constructs a VerificationKey from a private key.
    pub fn from_secret_decompressed(privkey: &Scalar) -> RistrettoPoint {
        (privkey * RISTRETTO_BASEPOINT_POINT)
    }

    /// Creates new key from a compressed form, remembers the compressed point.
    pub fn from_compressed(p: CompressedRistretto) -> Option<Self> {
        Some(VerificationKey { point: p })
    }

    /// Converts the Verification key to a compressed point
    pub fn into_point(self) -> CompressedRistretto {
        self.point
    }

    /// Returns a reference to the compressed ristretto point
    pub fn as_point(&self) -> &CompressedRistretto {
        &self.point
    }

    /// Returns the view into byte representation of the verification key
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.point.as_bytes()
    }

    /// Returns the byte representation of the verification key
    pub fn to_bytes(&self) -> [u8; 32] {
        self.point.to_bytes()
    }
}

impl From<RistrettoPoint> for VerificationKey {
    fn from(p: RistrettoPoint) -> Self {
        VerificationKey {
            point: p.compress(),
        }
    }
}

impl From<CompressedRistretto> for VerificationKey {
    fn from(p: CompressedRistretto) -> Self {
        VerificationKey { point: p }
    }
}

impl Into<CompressedRistretto> for VerificationKey {
    fn into(self) -> CompressedRistretto {
        self.into_point()
    }
}
