use crate::bit_range::BitRange;
use bulletproofs::r1cs::{ConstraintSystem, LinearCombination, R1CSError};
use curve25519_dalek::scalar::Scalar;

use crate::signed_integer::SignedInteger;

/// Enforces that the quantity of v is in the range [0, 2^n).
pub fn range_proof<CS: ConstraintSystem>(
    cs: &mut CS,
    mut v: LinearCombination,
    v_assignment: Option<SignedInteger>,
    n: BitRange,
) -> Result<(), R1CSError> {
    let mut exp_2 = Scalar::one();
    let n_usize: usize = n.into();
    for i in 0..n_usize {
        // Create low-level variables and add them to constraints
        let (a, b, o) = cs.allocate_multiplier(v_assignment.and_then(|q| {
            q.to_u64().map(|q| {
                let bit: u64 = (q >> i) & 1;
                ((1 - bit).into(), bit.into())
            })
        }))?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());

        // Enforce that a = 1 - b, so they both are 1 or 0.
        cs.constrain(a + (b - 1u64));

        // Add `-b_i*2^i` to the linear combination
        // in order to form the following constraint by the end of the loop:
        // v = Sum(b_i * 2^i, i = 0..n-1)
        v = v - b * exp_2;

        exp_2 = exp_2 + exp_2;
    }

    // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
    cs.constrain(v);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    #[test]
    fn range_proof_gadget() {
        use rand::thread_rng;
        use rand::Rng;

        let mut rng = thread_rng();
        let m = 3; // number of values to test per `n`

        for n in [2, 10, 32, 63].iter() {
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
            for v in values {
                assert!(range_proof_helper(v.into(), *n).is_ok());
            }
            assert!(range_proof_helper((max + 1).into(), *n).is_err());
        }
    }

    fn range_proof_helper(v_val: SignedInteger, n: usize) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let bit_width = BitRange::new(n).ok_or(R1CSError::GadgetError {
            description: "Invalid Bitrange; Bitrange must be between 0 and 64".to_string(),
        })?;

        // Prover's scope
        let (proof, commitment) = {
            // Prover makes a `ConstraintSystem` instance representing a range proof gadget
            let mut prover_transcript = Transcript::new(b"RangeProofTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

            let (com, var) = prover.commit(v_val.into(), Scalar::random(&mut rng));
            assert!(range_proof(&mut prover, var.into(), Some(v_val), bit_width).is_ok());

            let proof = prover.prove(&bp_gens)?;

            (proof, com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"RangeProofTest");
        let mut verifier = Verifier::new(&mut verifier_transcript);

        let var = verifier.commit(commitment);

        // Verifier adds constraints to the constraint system
        assert!(range_proof(&mut verifier, var.into(), None, bit_width).is_ok());

        // Verifier verifies proof
        Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
    }
}
