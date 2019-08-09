use crate::errors::SchnorrError;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::{Identity, IsIdentity, VartimeMultiscalarMul};

/// Deferred signature verification
#[derive(Clone, Debug)]
#[must_use = "Deferred verification must be completed with `verify` or `verify_batch`."]
pub struct DeferredVerification {
    /// Weight for the Ristretto base point.
    pub static_point_weight: Scalar,

    /// Weights for arbitrary points.
    pub dynamic_point_weights: Vec<(Scalar, CompressedRistretto)>,
}

impl DeferredVerification {
    /// Non-batched evaluation of a deferred signature verification.
    pub fn verify(self) -> Result<(), SchnorrError> {
        if !self.compute()?.is_identity() {
            return Err(SchnorrError::InvalidSignature);
        }
        Ok(())
    }

    fn compute(self) -> Result<RistrettoPoint, SchnorrError> {
        let (mut weights, points): (Vec<_>, Vec<_>) =
            self.dynamic_point_weights.into_iter().unzip();
        let mut points: Vec<_> = points.into_iter().map(|p| p.decompress()).collect();

        weights.push(self.static_point_weight);
        points.push(Some(RISTRETTO_BASEPOINT_POINT));

        if points.len() == 0 {
            return Ok(RistrettoPoint::identity());
        }

        RistrettoPoint::optional_multiscalar_mul(weights, points)
            .ok_or(SchnorrError::InvalidSignature)
    }

    /// Batched evaluation of deferred signature verification.
    pub fn verify_batch(batch: &[DeferredVerification]) -> Result<(), SchnorrError> {
        // Get the total number of points in batch
        let dyn_length: usize = batch.iter().map(|p| p.dynamic_point_weights.len()).sum();
        let length = 2 + dyn_length; // include the (B, B_blinding) pair

        let mut weights: Vec<Scalar> = Vec::with_capacity(length + 2);
        let mut points: Vec<Option<RistrettoPoint>> = Vec::with_capacity(length);

        // Add base points
        points.push(Some(RISTRETTO_BASEPOINT_POINT));
        weights.push(Scalar::zero());

        let mut rng = rand::thread_rng();

        // Iterate over every point, adding both weights and points to
        // our arrays
        for p in batch.iter() {
            // Sample free variable e
            let e = Scalar::random(&mut rng);

            weights[0] = weights[0] + e * p.static_point_weight;

            // Add weights and points for arbitrary points
            let arbitrary_scalars = p.dynamic_point_weights.iter().map(|p| p.0 * e);
            let arbitrary_points = p.dynamic_point_weights.iter().map(|p| p.1.decompress());
            weights.extend(arbitrary_scalars);
            points.extend(arbitrary_points);
        }

        let check = RistrettoPoint::optional_multiscalar_mul(weights, points)
            .ok_or(SchnorrError::InvalidSignature)?;
        if !check.is_identity() {
            return Err(SchnorrError::InvalidSignature);
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
        let v = DeferredVerification {
            static_point_weight: Scalar::zero(),
            dynamic_point_weights: Vec::new(),
        };
        assert!(v.verify().is_ok());
    }

    #[test]
    fn primary_generator() {
        let v = DeferredVerification {
            static_point_weight: Scalar::one(),
            dynamic_point_weights: vec![(-Scalar::one(), RISTRETTO_BASEPOINT_COMPRESSED)],
        };
        assert!(v.verify().is_ok());

        let v = DeferredVerification {
            static_point_weight: Scalar::one(),
            dynamic_point_weights: vec![(
                -Scalar::one(),
                (RISTRETTO_BASEPOINT_POINT * Scalar::from(4u8)).compress(),
            )],
        };
        assert!(v.verify().is_err());

        let v = DeferredVerification {
            static_point_weight: Scalar::one(),
            dynamic_point_weights: vec![(Scalar::one(), RISTRETTO_BASEPOINT_COMPRESSED)],
        };
        assert!(v.verify().is_err());
    }

    #[test]
    fn no_generators() {
        let v = DeferredVerification {
            static_point_weight: Scalar::zero(),
            dynamic_point_weights: vec![
                (-Scalar::one(), RISTRETTO_BASEPOINT_COMPRESSED),
                (Scalar::one(), RISTRETTO_BASEPOINT_COMPRESSED),
            ],
        };
        assert!(v.verify().is_ok());
    }
}
