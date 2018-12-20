use bulletproofs::r1cs::{ConstraintSystem, R1CSError, RandomizedConstraintSystem, Variable};

/// Enforces that the output variables `y` are a valid reordering of the inputs variables `x`.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    x: Vec<Variable>,
    y: Vec<Variable>,
) -> Result<(), R1CSError> {
    if x.len() != y.len() {
        return Err(R1CSError::GadgetError {
            description: "x and y vector lengths do not match in scalar shuffle".to_string(),
        });
    }

    let k = x.len();
    if k == 1 {
        cs.constrain(y[0] - x[0]);
        return Ok(());
    }

    cs.specify_randomized_constraints(move |cs| {
        let z = cs.challenge_scalar(b"shuffle challenge");

        // Make last x multiplier for i = k-1 and k-2
        let (_, _, last_mulx_out) = cs.multiply(x[k - 1] - z, x[k - 2] - z);

        // Make multipliers for x from i == [0, k-3]
        let first_mulx_out = (0..k - 2).rev().fold(last_mulx_out, |prev_out, i| {
            let (_, _, o) = cs.multiply(prev_out.into(), x[i] - z);
            o
        });

        // Make last y multiplier for i = k-1 and k-2
        let (_, _, last_muly_out) = cs.multiply(y[k - 1] - z, y[k - 2] - z);

        // Make multipliers for y from i == [0, k-3]
        let first_muly_out = (0..k - 2).rev().fold(last_muly_out, |prev_out, i| {
            let (_, _, o) = cs.multiply(prev_out.into(), y[i] - z);
            o
        });

        // Constrain last x mul output and last y mul output to be equal
        cs.constrain(first_mulx_out - first_muly_out);

        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use curve25519_dalek::ristretto::CompressedRistretto;
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;

    #[test]
    fn scalar_shuffle() {
        // k=1
        assert!(scalar_shuffle_helper(vec![3], vec![3]).is_ok());
        assert!(scalar_shuffle_helper(vec![6], vec![6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3], vec![6]).is_err());
        // k=2
        assert!(scalar_shuffle_helper(vec![3, 6], vec![3, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6], vec![6, 3]).is_ok());
        assert!(scalar_shuffle_helper(vec![6, 6], vec![6, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 3], vec![6, 3]).is_err());
        // k=3
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![3, 6, 10]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![3, 10, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![6, 3, 10]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![6, 10, 3]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![10, 3, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![10, 6, 3]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![30, 6, 10]).is_err());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![3, 60, 10]).is_err());
        assert!(scalar_shuffle_helper(vec![3, 6, 10], vec![3, 6, 100]).is_err());
        // k=4
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15], vec![3, 6, 10, 15]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15], vec![15, 6, 10, 3]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15], vec![3, 6, 10, 3]).is_err());
        // k=5
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15, 17], vec![3, 6, 10, 15, 17]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15, 17], vec![10, 17, 3, 15, 6]).is_ok());
        assert!(scalar_shuffle_helper(vec![3, 6, 10, 15, 17], vec![3, 6, 10, 15, 3]).is_err());
    }

    // This test allocates variables for the high-level variables, to check that high-level
    // variable allocation and commitment works.
    fn scalar_shuffle_helper(input: Vec<u64>, output: Vec<u64>) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        // Prover's scope
        let (proof, input_com, output_com) = {
            // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
            let mut prover_transcript = Transcript::new(b"ShuffleTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);

            let (input_com, input_vars): (Vec<CompressedRistretto>, Vec<Variable>) = input
                .iter()
                .map(|v| prover.commit(Scalar::from(*v), Scalar::random(&mut rng)))
                .unzip();
            let (output_com, output_vars): (Vec<CompressedRistretto>, Vec<Variable>) = output
                .iter()
                .map(|v| prover.commit(Scalar::from(*v), Scalar::random(&mut rng)))
                .unzip();

            fill_cs(&mut prover, input_vars, output_vars)?;
            let proof = prover.prove()?;

            (proof, input_com, output_com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"ShuffleTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let input_vars: Vec<Variable> = input_com.iter().map(|com| verifier.commit(*com)).collect();
        let output_vars: Vec<Variable> =
            output_com.iter().map(|com| verifier.commit(*com)).collect();

        // Verifier adds constraints to the constraint system
        fill_cs(&mut verifier, input_vars, output_vars)?;

        Ok(verifier.verify(&proof)?)
    }
}
