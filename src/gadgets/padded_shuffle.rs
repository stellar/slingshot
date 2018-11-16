use bulletproofs::r1cs::ConstraintSystem;
use curve25519_dalek::scalar::Scalar;
use std::cmp::{max, min};

use super::value_shuffle;
use error::SpacesuitError;
use value::{AllocatedValue, Value};

/// Enforces that the values in `y` are a valid reordering of the values in `x`,
/// allowing for padding (zero values) in x that can be omitted in y (or the other way around).
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    mut x: Vec<AllocatedValue>,
    mut y: Vec<AllocatedValue>,
) -> Result<(), SpacesuitError> {
    let m = x.len();
    let n = y.len();

    // Number of values to be padded on one side of the shuffle
    let pad_count = max(m, n) - min(m, n);
    let mut values = Vec::with_capacity(pad_count);

    for _ in 0..pad_count {
        // We need three independent variables constrained to be zeroes.
        // We can do that with a single multiplier and two linear constraints for the inputs only.
        // The multiplication constraint is enough to ensure that the third wire is also zero.
        let (q, a, t) = cs.multiply(Scalar::zero().into(), Scalar::zero().into());
        let assignment = Some(Value::zero());
        values.push(AllocatedValue {
            q,
            a,
            t,
            assignment,
        });
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
    use bulletproofs::r1cs::{ProverCS, Variable, VerifierCS};
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
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(4), zero(), zero(), yuan(4)],
                vec![zero(), yuan(4), yuan(4)]
            )
            .is_ok()
        );

        // k=3, with interspersed empty values
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), zero(), peso(8)],
                vec![yuan(1), yuan(4), peso(8)]
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), peso(8)],
                vec![yuan(1), zero(), peso(8), zero(), yuan(4)]
            )
            .is_ok()
        );
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), zero(), peso(8)],
                vec![zero(), zero(), yuan(4), yuan(1), peso(8)]
            )
            .is_ok()
        );
        assert!(padded_shuffle_helper(vec![peso(1), yuan(4)], vec![yuan(4), peso(2)]).is_err());
        assert!(
            padded_shuffle_helper(
                vec![yuan(1), yuan(4), peso(8)],
                vec![
                    zero(),
                    Value {
                        q: 1,
                        a: 0u64.into(),
                        t: 0u64.into()
                    },
                    yuan(4),
                    yuan(1),
                    peso(8)
                ]
            )
            .is_err()
        );
    }

    // Helper functions to make the tests easier to read
    fn yuan(q: u64) -> Value {
        Value {
            q,
            a: 888u64.into(),
            t: 999u64.into(),
        }
    }
    fn peso(q: u64) -> Value {
        Value {
            q,
            a: 666u64.into(),
            t: 777u64.into(),
        }
    }
    fn zero() -> Value {
        Value::zero()
    }

    fn padded_shuffle_helper(
        input: Vec<Value>,
        output: Vec<Value>,
    ) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let m = input.len();
        let n = output.len();

        // Prover's scope
        let (proof, commitments) = {
            let mut values = input.clone();
            values.append(&mut output.clone());

            let v: Vec<Scalar> = values.iter().fold(Vec::new(), |mut vec, value| {
                vec.push(value.q.into());
                vec.push(value.a);
                vec.push(value.t);
                vec
            });
            let v_blinding: Vec<Scalar> = (0..v.len())
                .map(|_| Scalar::random(&mut rand::thread_rng()))
                .collect();

            // Make v_blinding vector using RNG from transcript
            let mut prover_transcript = Transcript::new(b"PaddedShuffleTest");
            let (mut prover_cs, variables, commitments) = ProverCS::new(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                v.clone(),
                v_blinding,
            );

            let (input_vals, output_vals) = organize_values(variables, &Some(values), m, n);

            fill_cs(&mut prover_cs, input_vals, output_vals)?;
            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a shuffle gadget
        let mut verifier_transcript = Transcript::new(b"PaddedShuffleTest");
        let (mut verifier_cs, variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier allocates variables and adds constraints to the constraint system
        let (input_vals, output_vals) = organize_values(variables, &None, m, n);
        assert!(fill_cs(&mut verifier_cs, input_vals, output_vals).is_ok());

        // Verifier verifies proof
        Ok(verifier_cs.verify(&proof)?)
    }

    fn organize_values(
        variables: Vec<Variable>,
        assignments: &Option<Vec<Value>>,
        m: usize,
        n: usize,
    ) -> (Vec<AllocatedValue>, Vec<AllocatedValue>) {
        let mut inputs: Vec<AllocatedValue> = Vec::with_capacity(m);
        let mut outputs: Vec<AllocatedValue> = Vec::with_capacity(n);
        for i in 0..m {
            inputs.push(AllocatedValue {
                q: variables[i * 3],
                a: variables[i * 3 + 1],
                t: variables[i * 3 + 2],
                assignment: match assignments {
                    Some(ref a) => Some(a[i]),
                    None => None,
                },
            });
        }
        for i in m..(m + n) {
            outputs.push(AllocatedValue {
                q: variables[i * 3],
                a: variables[i * 3 + 1],
                t: variables[i * 3 + 2],
                assignment: match assignments {
                    Some(ref a) => Some(a[i]),
                    None => None,
                },
            });
        }

        (inputs, outputs)
    }
}
