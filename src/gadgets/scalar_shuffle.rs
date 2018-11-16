use bulletproofs::r1cs::{ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use error::SpacesuitError;

/// Enforces that the output variables `y` are a valid reordering of the inputs variables `x`.
/// The inputs and outputs are all tuples of the `Variable, Assignment`, where the `Assignment`
/// can be either assigned as `Value::Scalar` or unassigned as `Missing`.
pub fn fill_cs<CS: ConstraintSystem>(cs: &mut CS, x: &[Variable], y: &[Variable]) {
    let one = Scalar::one();
    let z = cs.challenge_scalar(b"k-scalar shuffle challenge");

    assert_eq!(x.len(), y.len());

    let k = x.len();
    if k == 1 {
        cs.constrain(y[0] - x[0]);
        return;
    }

    // Make last x multiplier for i = k-1 and k-2
    let (_, _, last_mulx_out) = cs.multiply(x[k - 1] - z, x[k - 2] - z)?;

    // Make multipliers for x from i == [0, k-3]
    let first_mulx_out = (0..k - 2).rev().fold(last_mulx_out, |prev_out, i| {
        let (_, _, o) = cs.multiply(prev_out.into(), x[i] - z)?;
        o
    });

    // Make last y multiplier for i = k-1 and k-2
    let (_, _, last_muly_out) = cs.multiply(y[k - 1] - z, y[k - 2] - z);

    // Make multipliers for y from i == [0, k-3]
    let first_muly_out = (0..k - 2).rev().fold(last_muly_out, |prev_out, i| {
        let (_, _, o) = cs.multiply(prev_out.into(), y[i] - z)?;
        o
    });

    // Check equality between last x mul output and last y mul output
    cs.constrain(first_muly_out - first_mulx_out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{ProverCS, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;

    #[test]
    fn scalar_shuffle_gadget() {
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
    fn scalar_shuffle_helper(input: Vec<u64>, output: Vec<u64>) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        let k = input.len();
        if k != output.len() {
            return Err(SpacesuitError::InvalidR1CSConstruction);
        }

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
            // Make v vector
            let mut v = vec![];
            for i in 0..k {
                v.push(Scalar::from(input[i]));
            }
            for i in 0..k {
                v.push(Scalar::from(output[i]));
            }

            // Make v_blinding vector using RNG from transcript
            let mut prover_transcript = Transcript::new(b"ShuffleTest");
            let mut rng = {
                let mut builder = prover_transcript.build_rng();

                // commit the secret values
                for &v_i in &v {
                    builder = builder.commit_witness_bytes(b"v_i", v_i.as_bytes());
                }

                use rand::thread_rng;
                builder.finalize(&mut thread_rng())
            };
            let v_blinding: Vec<Scalar> = (0..2 * k).map(|_| Scalar::random(&mut rng)).collect();

            let (mut prover_cs, variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v,
                v_blinding.clone(),
            );

            // Prover allocates variables and adds constraints to the constraint system
            let (input_vars, output_vars) = variables.split_at(k);
            fill_cs(&mut prover_cs, input_vars, output_vars);
            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"ShuffleTest");
        let (mut verifier_cs, variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let (input_vars, output_vars) = variables.split_at(k);
        fill_cs(&mut verifier_cs, input_vars, output_vars);

        // Verifier verifies proof
        Ok(verifier_cs.verify(&proof)?)
    }
}
