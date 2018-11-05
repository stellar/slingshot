use super::value_shuffle;
use bulletproofs::r1cs::{Assignment, ConstraintSystem};
use curve25519_dalek::scalar::Scalar;
use error::SpacesuitError;
use std::cmp::{max, min};
use value::Value;

/// Enforces that the values in `y` are a valid reordering of the values in `x`,
/// allowing for padding (zero values) in x that can be omitted in y (or the other way around).
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    mut x: Vec<Value>,
    mut y: Vec<Value>,
) -> Result<(), SpacesuitError> {
    let m = x.len();
    let n = y.len();

    // Number of values to be padded on one side of the shuffle
    let pad_count = max(m, n) - min(m, n);
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
        // Constrain each of the padding variables to be equal to zero.
        for var in vec![var_q, var_a, var_t] {
            cs.add_constraint([(var, Scalar::one())].iter().collect());
        }
    }

    if m > n {
        y.append(&mut values);
    } else if m < n {
        x.append(&mut values);
    }

    value_shuffle::fill_cs(cs, x, y)?;

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
            padded_shuffle_helper(vec![peso(1), zero(), yuan(4)], vec![peso(1), yuan(4)]).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![peso(1), yuan(4)],
                vec![zero(), yuan(4), zero(), peso(1)]
            ).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(4), zero(), zero(), yuan(4)],
                vec![zero(), yuan(4), yuan(4)]
            ).is_ok()
        );

        // k=3, with interspersed empty values
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), zero(), peso(8)],
                vec![yuan(1), yuan(4), peso(8)]
            ).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), peso(8)],
                vec![yuan(1), zero(), peso(8), zero(), yuan(4)]
            ).is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), zero(), peso(8)],
                vec![zero(), zero(), yuan(4), yuan(1), peso(8)]
            ).is_ok()
        );
        assert!(padded_shuffle_helper(vec![peso(1), yuan(4)], vec![yuan(4), peso(2)]).is_err());
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), peso(8)],
                vec![zero(), (1, 0, 0), yuan(4), yuan(1), peso(8)]
            ).is_err()
        );
    }

    // Helper functions to make the tests easier to read
    fn yuan(val: u64) -> (u64, u64, u64) {
        (val, 888, 999)
    }
    fn peso(val: u64) -> (u64, u64, u64) {
        (val, 666, 777)
    }
    fn zero() -> (u64, u64, u64) {
        (0, 0, 0)
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
                v.push(Scalar::from(tuple.2));
            }
            for tuple in output {
                v.push(Scalar::from(tuple.0));
                v.push(Scalar::from(tuple.1));
                v.push(Scalar::from(tuple.2));
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
