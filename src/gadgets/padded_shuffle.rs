use super::{pad, value_shuffle};
use bulletproofs::r1cs::{Assignment, ConstraintSystem};
use util::{SpacesuitError, Value};

// Enforces that all variables are equal to zero.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    x: Vec<Value>,
    y: Vec<Value>,
) -> Result<(), SpacesuitError> {
    let m = x.len();
    let n = y.len();

    // Number of values to be padded on one side of the shuffle
    let pad_count = (m as i8 - n as i8).abs() as usize;
    let mut values = Vec::with_capacity(pad_count);

    for _ in 0..pad_count {
        // We can use assign_multiplier (instead of assign_uncommitted) because we know that 0 * 0 = 0.
        let (var_q, var_a, var_t) = cs.assign_multiplier(
            Assignment::from(0),
            Assignment::from(0),
            Assignment::from(0),
        )?;
        values.push(Value {
            q: (var_q, Assignment::from(0)),
            a: (var_a, Assignment::from(0)),
            t: (var_t, Assignment::from(0)),
        });
        pad::fill_cs(cs, vec![var_q, var_a, var_t])?;
    }

    if m > n {
        let mut y_padded = y.clone();
        y_padded.append(&mut values);
        value_shuffle::fill_cs(cs, x, y_padded)?;
    } else if m < n {
        let mut x_padded = x.clone();
        x_padded.append(&mut values);
        value_shuffle::fill_cs(cs, x_padded, y)?;
    } else {
        value_shuffle::fill_cs(cs, x, y)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Assignment, ProverCS, Variable, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use curve25519_dalek::scalar::Scalar;
    use merlin::Transcript;

    #[test]
    fn padded_shuffle() {
        // k=2, with interspersed empty values
        assert!(
            padded_shuffle_helper(
                vec![(1, 2, 3), (0, 0, 0), (4, 5, 6)],
                vec![(1, 2, 3), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6)],
                vec![(0, 0, 0), (4, 5, 6), (0, 0, 0), (1, 2, 3)]
            ).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![(4, 5, 6), (0, 0, 0), (0, 0, 0), (4, 5, 6)],
                vec![(0, 0, 0), (4, 5, 6), (4, 5, 6)]
            ).is_ok()
        );

        // k=3, with interspersed empty values
        assert!(
            padded_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (0, 0, 0), (8, 9, 10)],
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)]
            ).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (8, 9, 10)],
                vec![(1, 2, 3), (0, 0, 0), (8, 9, 10), (0, 0, 0), (4, 5, 6)]
            ).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![(1, 2, 3), (4, 5, 6), (0, 0, 0), (8, 9, 10)],
                vec![(0, 0, 0), (0, 0, 0), (4, 5, 6), (1, 2, 3), (8, 9, 10)]
            ).is_ok()
        );
    }

    fn padded_shuffle_helper(
        input: Vec<(u64, u64, u64)>,
        output: Vec<(u64, u64, u64)>,
    ) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let m = input.len();
        let n = output.len();

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a shuffle gadget
            // make v vector
            let mut v = Vec::with_capacity(m * 3 + n * 3);
            for tuple in input {
                v.push(Scalar::from(tuple.0));
                v.push(Scalar::from(tuple.1));
                v.push(Scalar::from(tuple.1));
            }
            for tuple in output {
                v.push(Scalar::from(tuple.0));
                v.push(Scalar::from(tuple.1));
                v.push(Scalar::from(tuple.1));
            }

            // Make v_blinding vector using RNG from transcript
            let mut prover_transcript = Transcript::new(b"PaddedShuffleTest");
            let mut rng = {
                let mut builder = prover_transcript.build_rng();

                // Commit the secret values
                for &v_i in &v {
                    builder = builder.commit_witness_bytes(b"v_i", v_i.as_bytes());
                }
                use rand::thread_rng;
                builder.finalize(&mut thread_rng())
            };
            let v_blinding: Vec<Scalar> = (0..v.len()).map(|_| Scalar::random(&mut rng)).collect();

            let (mut prover_cs, variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v.clone(),
                v_blinding,
            );

            let v_assignments = v.iter().map(|v_i| Assignment::from(*v_i)).collect();
            let (input_vals, output_vals) = value_helper(variables, v_assignments, m);

            fill_cs(&mut prover_cs, input_vals, output_vals)?;
            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"PaddedShuffleTest");
        let (mut verifier_cs, variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let v_assignments = vec![Assignment::Missing(); variables.len()];
        let (input_vals, output_vals) = value_helper(variables, v_assignments, m);
        assert!(fill_cs(&mut verifier_cs, input_vals, output_vals).is_ok());

        // Verifier verifies proof
        Ok(verifier_cs.verify(&proof)?)
    }

    fn value_helper(
        variables: Vec<Variable>,
        assignments: Vec<Assignment>,
        m: usize,
    ) -> (Vec<Value>, Vec<Value>) {
        let val_count = variables.len() / 3;
        let mut values = Vec::with_capacity(val_count);
        for i in 0..val_count {
            values.push(Value {
                q: (variables[i * 3], assignments[i * 3]),
                a: (variables[i * 3 + 1], assignments[i * 3 + 1]),
                t: (variables[i * 3 + 2], assignments[i * 3 + 2]),
            });
        }

        let input = values[0..m].to_vec();
        let output = values[m..values.len()].to_vec();

        (input, output)
    }
}
