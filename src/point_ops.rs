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
        let gens = PedersenGens::default();

        // Get the total number of points in batch
        let dyn_length: usize = batch.iter().map(|p| p.arbitrary.len()).sum();
        let length = 2 + dyn_length; // include the (B, B_blinding) pair

        let mut weights: Vec<Scalar> = Vec::with_capacity(length + 2);
        let mut points: Vec<Option<RistrettoPoint>> = Vec::with_capacity(length);

        // Add base points
        points.push(Some(gens.B));
        points.push(Some(gens.B_blinding));
        weights.push(Scalar::zero());
        weights.push(Scalar::zero());

        let mut rng = rand::thread_rng();

        // Iterate over every point, adding both weights and points to
        // our arrays
        for p in batch.iter() {
            // Sample free variable e
            let e = Scalar::random(&mut rng);

            // Add weights for base points
            if let Some(w) = p.primary {
                weights[0] = weights[0] + e * w;
            }
            if let Some(w) = p.secondary {
                weights[1] = weights[1] + e * w;
            }

            // Add weights and points for arbitrary points
            let arbitrary_scalars = p.arbitrary.iter().map(|p| p.0 * e);
            let arbitrary_points = p.arbitrary.iter().map(|p| p.1.decompress());
            weights.extend(arbitrary_scalars);
            points.extend(arbitrary_points);
        }

        let check = RistrettoPoint::optional_multiscalar_mul(weights, points)
            .ok_or_else(|| VMError::PointOperationFailed)?;
        if !check.is_identity() {
            return Err(VMError::PointOperationFailed);
        }

        Ok(())
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

    #[test]
    fn batch_verify() {
        let gens = PedersenGens::default();
        let op1 = PointOp {
            primary: Some(Scalar::one()),
            secondary: Some(Scalar::one()),
            arbitrary: vec![
                (-Scalar::one(), gens.B_blinding.compress()),
                (-Scalar::one(), gens.B.compress()),
            ],
        };
        let op2 = PointOp {
            primary: None,
            secondary: Some(Scalar::one()),
            arbitrary: vec![(-Scalar::one(), gens.B_blinding.compress())],
        };
        assert!(PointOp::verify_batch(&[op1, op2]).is_ok());
    }
}
