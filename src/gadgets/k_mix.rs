#![allow(non_snake_case)]

use super::mix;
use bulletproofs::r1cs::ConstraintSystem;
use curve25519_dalek::scalar::Scalar;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use util::{SpacesuitError, Value};

/// Enforces that the outputs are either a merge of the inputs :`D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`.
/// Works for `k` inputs and `k` outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    intermediates: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
    let one = Scalar::one();
    if inputs.len() == 1 && outputs.len() == 1 {
        cs.add_constraint(
            [(inputs[0].q.0, -one), (outputs[0].q.0, one)]
                .iter()
                .collect(),
        );
        cs.add_constraint(
            [(inputs[0].a.0, -one), (outputs[0].a.0, one)]
                .iter()
                .collect(),
        );
        cs.add_constraint(
            [(inputs[0].t.0, -one), (outputs[0].t.0, one)]
                .iter()
                .collect(),
        );
        return Ok(());
    }

    if inputs.len() != outputs.len() || intermediates.len() != inputs.len() - 2 {
        return Err(SpacesuitError::InvalidR1CSConstruction);
    }

    let mut A = inputs[0].clone();
    let mut B = inputs[1].clone();
    let mut C = outputs[0].clone();

    for i in 0..inputs.len() - 2 {
        let mut D = intermediates[i].clone();

        mix::fill_cs(cs, A, B, C, D)?;

        A = intermediates[i].clone();
        B = inputs[i + 2].clone();
        C = outputs[i + 1].clone();
    }

    let D = outputs[outputs.len() - 1].clone();
    mix::fill_cs(cs, A, B, C, D)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Assignment, ProverCS, Variable, VerifierCS};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use std::cmp::max;

    #[test]
    fn k_mix_gadget() {
        let peso = 66;
        let yuan = 88;
        let zero = 0; // just so the test case formatting lines up nicely

        // k=1
        // no merge, same asset types
        assert!(k_mix_helper(vec![(6, peso, 0)], vec![], vec![(6, peso, 0)]).is_ok());
        // error when merging different asset types
        assert!(k_mix_helper(vec![(3, peso, 0)], vec![], vec![(3, yuan, 0)]).is_err());

        // k=2 ... more extensive k=2 tests are in the MixGadget tests
        // no merge, different asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, yuan, 0)],
                vec![],
                vec![(3, peso, 0), (6, yuan, 0)],
            ).is_ok()
        );
        // merge, same asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0)],
                vec![],
                vec![(0, peso, 0), (9, peso, 0)],
            ).is_ok()
        );
        // error when merging different asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (3, yuan, 0)],
                vec![],
                vec![(0, peso, 0), (6, yuan, 0)],
            ).is_err()
        );

        // k=3
        // no merge, same asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (6, peso, 0)],
                vec![(6, peso, 0)],
                vec![(3, peso, 0), (6, peso, 0), (6, peso, 0)],
            ).is_ok()
        );
        // no merge, different asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, yuan, 0), (6, peso, 0)],
                vec![(6, yuan, 0)],
                vec![(3, peso, 0), (6, yuan, 0), (6, peso, 0)],
            ).is_ok()
        );
        // merge first two
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (1, yuan, 0)],
                vec![(9, peso, 0)],
                vec![(0, peso, 0), (9, peso, 0), (1, yuan, 0)],
            ).is_ok()
        );
        // merge last two
        assert!(
            k_mix_helper(
                vec![(1, yuan, 0), (3, peso, 0), (6, peso, 0)],
                vec![(3, peso, 0)],
                vec![(1, yuan, 0), (0, peso, 0), (9, peso, 0)],
            ).is_ok()
        );
        // merge all, same asset types, zero value is different asset type
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (1, peso, 0)],
                vec![(9, peso, 0)],
                vec![(0, zero, 0), (0, zero, 0), (10, peso, 0)],
            ).is_ok()
        );
        // incomplete merge, input sum does not equal output sum
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (1, peso, 0)],
                vec![(9, peso, 0)],
                vec![(1, zero, 0), (0, zero, 0), (9, peso, 0)],
            ).is_err()
        );
        // error when merging with different asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, yuan, 0), (1, peso, 0)],
                vec![(9, peso, 0)],
                vec![(0, zero, 0), (0, zero, 0), (10, peso, 0)],
            ).is_err()
        );

        // k=4
        // merge each of 2 asset types
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (6, peso, 0), (1, yuan, 0), (2, yuan, 0)],
                vec![(9, peso, 0), (1, yuan, 0)],
                vec![(0, zero, 0), (9, peso, 0), (0, zero, 0), (3, yuan, 0)],
            ).is_ok()
        );
        // merge all, same asset
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (2, peso, 0), (2, peso, 0), (1, peso, 0)],
                vec![(5, peso, 0), (7, peso, 0)],
                vec![(0, zero, 0), (0, zero, 0), (0, zero, 0), (8, peso, 0)],
            ).is_ok()
        );
        // error when merging, output sum not equal to input sum
        assert!(
            k_mix_helper(
                vec![(3, peso, 0), (2, peso, 0), (2, peso, 0), (1, peso, 0)],
                vec![(5, peso, 0), (7, peso, 0)],
                vec![(0, zero, 0), (0, zero, 0), (0, zero, 0), (9, peso, 0)],
            ).is_err()
        );
    }

    fn k_mix_helper(
        inputs: Vec<(u64, u64, u64)>,
        intermediates: Vec<(u64, u64, u64)>,
        outputs: Vec<(u64, u64, u64)>,
    ) -> Result<(), SpacesuitError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let k = inputs.len();
        let inter_count = intermediates.len();
        if k != outputs.len() || inter_count != max(k as isize - 2, 0) as usize {
            return Err(SpacesuitError::InvalidR1CSConstruction);
        }

        // Prover's scope
        let (proof, commitments) = {
            // Prover makes a `ConstraintSystem` instance representing a merge gadget
            // Make v vector
            let mut v = Vec::with_capacity(6 * k);
            for i in 0..k {
                v.push(Scalar::from(inputs[i].0));
                v.push(Scalar::from(inputs[i].1));
                v.push(Scalar::from(inputs[i].2));
            }
            for i in 0..inter_count {
                v.push(Scalar::from(intermediates[i].0));
                v.push(Scalar::from(intermediates[i].1));
                v.push(Scalar::from(intermediates[i].2));
            }

            for i in 0..k {
                v.push(Scalar::from(outputs[i].0));
                v.push(Scalar::from(outputs[i].1));
                v.push(Scalar::from(outputs[i].2));
            }

            // Make v_blinding vector using RNG from transcript
            let mut prover_transcript = Transcript::new(b"KMixTest");
            let mut rng = {
                let mut builder = prover_transcript.build_rng();

                // commit the secret values
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
                v_blinding.clone(),
            );

            // Prover adds constraints to the constraint system
            let v_assignments = v.iter().map(|v_i| Assignment::from(*v_i)).collect();
            let (input_vals, inter_vals, output_vals) =
                value_helper(variables, v_assignments, k, inter_count);

            fill_cs(&mut prover_cs, input_vals, inter_vals, output_vals)?;

            let proof = prover_cs.prove()?;

            (proof, commitments)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"KMixTest");
        let (mut verifier_cs, variables) =
            VerifierCS::new(&bp_gens, &pc_gens, &mut verifier_transcript, commitments);

        // Verifier adds constraints to the constraint system
        let v_assignments = vec![Assignment::Missing(); variables.len()];
        let (input_vals, inter_vals, output_vals) =
            value_helper(variables, v_assignments, k, inter_count);

        assert!(fill_cs(&mut verifier_cs, input_vals, inter_vals, output_vals).is_ok());

        Ok(verifier_cs.verify(&proof)?)
    }

    fn value_helper(
        variables: Vec<Variable>,
        assignments: Vec<Assignment>,
        k: usize,
        inter_count: usize,
    ) -> (Vec<Value>, Vec<Value>, Vec<Value>) {
        let val_count = variables.len() / 3;

        let mut values = Vec::with_capacity(val_count);
        for i in 0..val_count {
            values.push(Value {
                q: (variables[i * 3], assignments[i * 3]),
                a: (variables[i * 3 + 1], assignments[i * 3 + 1]),
                t: (variables[i * 3 + 2], assignments[i * 3 + 2]),
            });
        }

        let input_vals = values[0..k].to_vec();
        let inter_vals = values[k..k + inter_count].to_vec();
        let output_vals = values[k + inter_count..2 * k + inter_count].to_vec();

        (input_vals, inter_vals, output_vals)
    }
}
