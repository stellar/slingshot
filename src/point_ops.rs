use bulletproofs::PedersenGens;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{IsIdentity, VartimeMultiscalarMul};

use super::errors::VMError;

/// Deferred point operation.
#[derive(Clone, Debug)]
pub struct PointOp {
    /// Weight for the primary generator.
    /// None stands for zero.
    pub primary: Option<Scalar>, // B

    /// Weight for the secondary generator.
    /// None stands for zero.
    pub secondary: Option<Scalar>, // B_blinding aka B2

    /// Weights for arbitrary points.
    pub arbitrary: Vec<(Scalar, CompressedRistretto)>,
}

impl PointOp {
    /// Non-batched verification of an individual point operation.
    pub fn verify(self, gens: &PedersenGens) -> Result<(), VMError> {
        let (mut weights, points): (Vec<_>, Vec<_>) = self.arbitrary.into_iter().unzip();
        let mut points: Vec<_> = points.into_iter().map(|p| p.decompress()).collect();

        if let Some(w) = self.primary {
            weights.push(w);
            points.push(Some(gens.B));
        }
        if let Some(w) = self.secondary {
            weights.push(w);
            points.push(Some(gens.B_blinding));
        }

        if points.len() == 0 {
            return Ok(());
        }

        let check = RistrettoPoint::optional_multiscalar_mul(weights, points)
            .ok_or_else(|| VMError::PointOperationFailed)?;

        if !check.is_identity() {
            return Err(VMError::PointOperationFailed);
        }

        Ok(())
    }

    /// Verifies a batch of point operations using one multi-scalar multiplication
    pub fn verify_batch(batch: &[PointOp]) -> Result<(), VMError> {
        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let gens = PedersenGens::default();
        let op = PointOp {
            primary: None,
            secondary: None,
            arbitrary: Vec::new(),
        };
        assert!(op.verify(&gens).is_ok());
    }

    #[test]
    fn primary_generator() {
        let gens = PedersenGens::default();
        let op = PointOp {
            primary: Some(Scalar::one()),
            secondary: None,
            arbitrary: vec![(-Scalar::one(), gens.B.compress())],
        };
        assert!(op.verify(&gens).is_ok());

        let op = PointOp {
            primary: Some(Scalar::one()),
            secondary: None,
            arbitrary: vec![(-Scalar::one(), gens.B_blinding.compress())],
        };
        assert!(op.verify(&gens).is_err());

        let op = PointOp {
            primary: Some(Scalar::one()),
            secondary: None,
            arbitrary: vec![(Scalar::one(), gens.B.compress())],
        };
        assert!(op.verify(&gens).is_err());
    }

    #[test]
    fn secondary_generator() {
        let gens = PedersenGens::default();
        let op = PointOp {
            primary: None,
            secondary: Some(Scalar::one()),
            arbitrary: vec![(-Scalar::one(), gens.B_blinding.compress())],
        };
        assert!(op.verify(&gens).is_ok());

        let op = PointOp {
            primary: None,
            secondary: Some(Scalar::one()),
            arbitrary: vec![(-Scalar::one(), gens.B.compress())],
        };
        assert!(op.verify(&gens).is_err());

        let op = PointOp {
            primary: None,
            secondary: Some(Scalar::one()),
            arbitrary: vec![(Scalar::one(), gens.B_blinding.compress())],
        };
        assert!(op.verify(&gens).is_err());
    }

    #[test]
    fn both_generators() {
        let gens = PedersenGens::default();
        let op = PointOp {
            primary: Some(Scalar::one()),
            secondary: Some(Scalar::one()),
            arbitrary: vec![
                (-Scalar::one(), gens.B_blinding.compress()),
                (-Scalar::one(), gens.B.compress()),
            ],
        };
        assert!(op.verify(&gens).is_ok());
    }

    #[test]
    fn no_generators() {
        let gens = PedersenGens::default();
        let op = PointOp {
            primary: None,
            secondary: None,
            arbitrary: vec![
                (-Scalar::one(), gens.B.compress()),
                (Scalar::one(), gens.B.compress()),
            ],
        };
        assert!(op.verify(&gens).is_ok());
    }
}
