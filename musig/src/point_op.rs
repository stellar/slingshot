use crate::errors::MuSigError;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::{RistrettoPoint, CompressedRistretto};
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::traits::{Identity, IsIdentity, VartimeMultiscalarMul};


/// Deferred point operation.
#[derive(Clone, Debug)]
pub struct PointOp {
    /// Weight for the primary generator.
    /// None stands for zero.
    pub primary: Option<Scalar>, // B

    /// Weights for arbitrary points.
    pub arbitrary: Vec<(Scalar, CompressedRistretto)>,
}

impl PointOp {
    /// Compute an individual point operation.
    pub fn compute(self) -> Result<RistrettoPoint, MuSigError> {
        let (mut weights, points): (Vec<_>, Vec<_>) = self.arbitrary.into_iter().unzip();
        let mut points: Vec<_> = points.into_iter().map(|p| p.decompress()).collect();

        if let Some(w) = self.primary {
            weights.push(w);
            points.push(Some(RISTRETTO_BASEPOINT_POINT));
        }

        if points.len() == 0 {
            return Ok(RistrettoPoint::identity());
        }

        RistrettoPoint::optional_multiscalar_mul(weights, points)
            .ok_or(MuSigError::PointOperationFailed)
    }

    /// Non-batched verification of an individual point operation
    pub fn verify(self) -> Result<(), MuSigError> {
        if !self.compute()?.is_identity() {
            return Err(MuSigError::PointOperationFailed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_dalek::constants::RISTRETTO_BASEPOINT_COMPRESSED;

    #[test]
    fn empty() {
        let op = PointOp {
            primary: None,
            arbitrary: Vec::new(),
        };
        assert!(op.verify().is_ok());
    }

    #[test]
    fn primary_generator() {
        let op = PointOp {
            primary: Some(Scalar::one()),
            arbitrary: vec![(-Scalar::one(), RISTRETTO_BASEPOINT_COMPRESSED)],
        };
        assert!(op.verify().is_ok());

        let op = PointOp {
            primary: Some(Scalar::one()),
            arbitrary: vec![(-Scalar::one(), (RISTRETTO_BASEPOINT_POINT*Scalar::from(4u8)).compress())],
        };
        assert!(op.verify().is_err());

        let op = PointOp {
            primary: Some(Scalar::one()),
            arbitrary: vec![(Scalar::one(), RISTRETTO_BASEPOINT_COMPRESSED)],
        };
        assert!(op.verify().is_err());
    }

    #[test]
    fn no_generators() {
        let op = PointOp {
            primary: None,
            arbitrary: vec![
                (-Scalar::one(), RISTRETTO_BASEPOINT_COMPRESSED),
                (Scalar::one(), RISTRETTO_BASEPOINT_COMPRESSED),
            ],
        };
        assert!(op.verify().is_ok());
    }
}