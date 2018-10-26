use bulletproofs::r1cs::{Assignment, ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use util::SpacesuitError;

/// Enforces that the quantity of v is in the range [0, 2^n).
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    v: (Variable, Assignment),
    n: usize,
) -> Result<(), SpacesuitError> {
    let one = Scalar::one();
    let one_var = Variable::One();

    let mut constraint = vec![(v.0, -one)];
    let mut exp_2 = Scalar::one();
    for i in 0..n {
        // Create low-level variables and add them to constraints
        let (a_i_var, b_i_var, out_var) = match v.1 {
            Assignment::Value(v_val) => {
                let bit = (v_val[i / 8] >> (i % 8)) & 1;
                cs.assign_multiplier(
                    Assignment::from(1 - bit as u64),
                    Assignment::from(bit as u64),
                    Scalar::zero().into(),
                )?
            }
            Assignment::Missing() => cs.assign_multiplier(
                Assignment::Missing(),
                Assignment::Missing(),
                Assignment::Missing(),
            )?,
        };

        // Enforce a_i * b_i = 0
        cs.add_constraint([(out_var, one)].iter().collect());

        // Enforce that a_i = 1 - b_i
        cs.add_constraint(
            [(a_i_var, one), (b_i_var, one), (one_var, -one)]
                .iter()
                .collect(),
        );

        constraint.push((b_i_var, exp_2));
        exp_2 = exp_2 + exp_2;
    }

    // Enforce that v = Sum(b_i * 2^i, i = 0..n-1)
    cs.add_constraint(constraint.iter().collect());

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{ProverCS, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    #[test]
    fn range_proof_gadget() {
        use rand::rngs::OsRng;
        use rand::Rng;

        let mut rng = OsRng::new().unwrap();
        let m = 3; // number of values to test per `n`

        for n in [2, 10, 32, 63].iter() {
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);
            let values: Vec<u64> = (0..m).map(|_| rng.gen_range(min, max)).collect();
            for v in values {
                assert!(range_proof_helper(v, *n).is_ok());
            }
            assert!(range_proof_helper(max + 1, *n).is_err());
        }
    }

    fn range_proof_helper(v_val: u64, n: usize) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            // v and v_blinding emptpy because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"RangeProofTest");
            let (mut prover_cs, _variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let (v_var, _) =
                prover_cs.assign_uncommitted(Assignment::from(v_val), Scalar::zero().into())?;

            fill_cs(&mut prover_cs, (v_var, Assignment::from(v_val)), n)?;

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"RangeProofTest");
        let (mut verifier_cs, _variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let (v_var, _) =
            verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;

        assert!(fill_cs(&mut verifier_cs, (v_var, Assignment::Missing()), n).is_ok());

        Ok(verifier_cs.verify(&proof)?)
    }
}
