use bulletproofs::r1cs::{ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use util::SpacesuitError;

// Enforces that all variables are equal to zero.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    vars: Vec<Variable>,
) -> Result<(), SpacesuitError> {
    for var in vars {
        cs.add_constraint(
            [(var, Scalar::one()), (Variable::One(), Scalar::zero())]
                .iter()
                .collect(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{ProverCS, VerifierCS, Assignment};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    #[test]
    fn pad_gadget() {
        assert!(pad_helper(vec![0]).is_ok());
        assert!(pad_helper(vec![0; 5]).is_ok());
        assert!(pad_helper(vec![0; 10]).is_ok());
        assert!(pad_helper(vec![1]).is_err());
        assert!(pad_helper(vec![0, 2, 0, 0, 0]).is_err());
    }

    fn pad_helper(vals: Vec<u64>) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let k = vals.len();

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            // v and v_blinding emptpy because we are only testing low-level variable constraints
            let v = vec![];
            let v_blinding = vec![];
            let mut prover_transcript = Transcript::new(b"PadTest");
            let (mut prover_cs, _variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let mut vars = Vec::with_capacity(k);
            for i in 0..k / 2 {
                let (var_a, var_b) = prover_cs
                    .assign_uncommitted(Assignment::from(vals[i]), Assignment::from(vals[i + 1]))?;
                vars.push(var_a);
                vars.push(var_b);
            }
            if k % 2 == 1 {
                let (var, _) = prover_cs.assign_uncommitted(
                    Assignment::from(vals[vals.len() - 1]),
                    Scalar::zero().into(),
                )?;
                vars.push(var);
            }

            fill_cs(&mut prover_cs, vars)?;

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"PadTest");
        let (mut verifier_cs, _variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let mut vars = Vec::with_capacity(k);
        for _ in 0..k / 2 {
            let (var_a, var_b) =
                verifier_cs.assign_uncommitted(Assignment::Missing(), Assignment::Missing())?;
            vars.push(var_a);
            vars.push(var_b);
        }
        if k % 2 == 1 {
            let (var, _) =
                verifier_cs.assign_uncommitted(Assignment::Missing(), Scalar::zero().into())?;
            vars.push(var);
        }

        assert!(fill_cs(&mut verifier_cs, vars).is_ok());

        Ok(verifier_cs.verify(&proof)?)
    }
}