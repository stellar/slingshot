#![allow(non_snake_case)]

use super::mix;
use bulletproofs::r1cs::ConstraintSystem;
use error::SpacesuitError;
use std::iter::once;
use value::AllocatedValue;

/// Enforces that the outputs are either a merge of the inputs: `D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for `k` inputs and `k` outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<AllocatedValue>,
    intermediates: Vec<AllocatedValue>,
    outputs: Vec<AllocatedValue>,
) -> Result<(), SpacesuitError> {
    // If there is only one input and output, just constrain the input
    // and output to be equal to each other.
    if inputs.len() == 1 && outputs.len() == 1 {
        let i = inputs[0];
        let o = outputs[0];
        cs.constrain(i.q - o.q);
        cs.constrain(i.a - o.a);
        cs.constrain(i.t - o.t);
        return Ok(());
    }

    if inputs.len() != outputs.len() || intermediates.len() != (inputs.len() - 2) {
        return Err(SpacesuitError::InvalidR1CSConstruction);
    }

    let first_input = inputs[0].clone();
    let last_output = outputs[outputs.len() - 1].clone();

    // For each 2-mix, constrain A, B, C, D:
    for (((A, B), C), D) in
        // A = (first_input||intermediates)[i]
        once(first_input).chain(intermediates.clone().into_iter())
        // B = inputs[i+1]
        .zip(inputs.into_iter().skip(1))
        // C = outputs[i]
        .zip(outputs.into_iter())
        // D = (intermediates||last_output)[i]
        .zip(intermediates.into_iter().chain(once(last_output)))
    {
        mix::fill_cs(cs, A, B, C, D)
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use std::cmp::max;
    use value::{ProverCommittable, Value, VerifierCommittable};

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

    #[test]
    fn k_mix_gadget() {
        // k=1
        // no merge, same asset types
        assert!(k_mix_helper(vec![peso(6)], vec![], vec![peso(6)]).is_ok());
        // error when merging different asset types
        assert!(k_mix_helper(vec![peso(3)], vec![], vec![yuan(3)]).is_err());

        // k=2. More extensive k=2 tests are in the MixGadget tests
        // no merge, different asset types
        assert!(k_mix_helper(vec![peso(3), yuan(6)], vec![], vec![peso(3), yuan(6)],).is_ok());
        // merge, same asset types
        assert!(k_mix_helper(vec![peso(3), peso(6)], vec![], vec![peso(0), peso(9)],).is_ok());
        // error when merging different asset types
        assert!(k_mix_helper(vec![peso(3), yuan(3)], vec![], vec![peso(0), yuan(6)],).is_err());

        // k=3
        // no merge, same asset types
        assert!(
            k_mix_helper(
                vec![peso(3), peso(6), peso(6)],
                vec![peso(6)],
                vec![peso(3), peso(6), peso(6)],
            )
            .is_ok()
        );
        // no merge, different asset types
        assert!(
            k_mix_helper(
                vec![peso(3), yuan(6), peso(6)],
                vec![yuan(6)],
                vec![peso(3), yuan(6), peso(6)],
            )
            .is_ok()
        );
        // merge first two
        assert!(
            k_mix_helper(
                vec![peso(3), peso(6), yuan(1)],
                vec![peso(9)],
                vec![peso(0), peso(9), yuan(1)],
            )
            .is_ok()
        );
        // merge last two
        assert!(
            k_mix_helper(
                vec![yuan(1), peso(3), peso(6)],
                vec![peso(3)],
                vec![yuan(1), peso(0), peso(9)],
            )
            .is_ok()
        );
        // merge all, same asset types, zero value is different asset type
        assert!(
            k_mix_helper(
                vec![peso(3), peso(6), peso(1)],
                vec![peso(9)],
                vec![zero(), zero(), peso(10)],
            )
            .is_ok()
        );
        // incomplete merge, input sum does not equal output sum
        assert!(
            k_mix_helper(
                vec![peso(3), peso(6), peso(1)],
                vec![peso(9)],
                vec![zero(), zero(), peso(9)],
            )
            .is_err()
        );
        // error when merging with different asset types
        assert!(
            k_mix_helper(
                vec![peso(3), yuan(6), peso(1)],
                vec![peso(9)],
                vec![zero(), zero(), peso(10)],
            )
            .is_err()
        );

        // k=4
        // merge each of 2 asset types
        assert!(
            k_mix_helper(
                vec![peso(3), peso(6), yuan(1), yuan(2)],
                vec![peso(9), yuan(1)],
                vec![zero(), peso(9), zero(), yuan(3)],
            )
            .is_ok()
        );
        // merge all, same asset
        assert!(
            k_mix_helper(
                vec![peso(3), peso(2), peso(2), peso(1)],
                vec![peso(5), peso(7)],
                vec![zero(), zero(), zero(), peso(8)],
            )
            .is_ok()
        );
        // no merge, different assets
        assert!(
            k_mix_helper(
                vec![peso(3), yuan(2), peso(2), yuan(1)],
                vec![yuan(2), peso(2)],
                vec![peso(3), yuan(2), peso(2), yuan(1)],
            )
            .is_ok()
        );
        // error when merging, output sum not equal to input sum
        assert!(
            k_mix_helper(
                vec![peso(3), peso(2), peso(2), peso(1)],
                vec![peso(5), peso(7)],
                vec![zero(), zero(), zero(), peso(9)],
            )
            .is_err()
        );
    }

    fn k_mix_helper(
        inputs: Vec<Value>,
        intermediates: Vec<Value>,
        outputs: Vec<Value>,
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
        let (proof, input_com, inter_com, output_com) = {
            let mut prover_transcript = Transcript::new(b"KMixTest");
            let mut rng = rand::thread_rng();

            let mut prover = Prover::new(&bp_gens, &pc_gens, &mut prover_transcript);
            let (input_com, input_vars) = inputs.commit(&mut prover, &mut rng);
            let (inter_com, inter_vars) = intermediates.commit(&mut prover, &mut rng);
            let (output_com, output_vars) = outputs.commit(&mut prover, &mut rng);

            fill_cs(&mut prover, input_vars, inter_vars, output_vars)?;

            let proof = prover.prove()?;
            (proof, input_com, inter_com, output_com)
        };

        // Verifier makes a `ConstraintSystem` instance representing a merge gadget
        let mut verifier_transcript = Transcript::new(b"KMixTest");
        let mut verifier = Verifier::new(&bp_gens, &pc_gens, &mut verifier_transcript);

        let input_vars = input_com.commit(&mut verifier);
        let inter_vars = inter_com.commit(&mut verifier);
        let output_vars = output_com.commit(&mut verifier);

        // Verifier adds constraints to the constraint system
        assert!(fill_cs(&mut verifier, input_vars, inter_vars, output_vars).is_ok());

        Ok(verifier.verify(&proof)?)
    }
}
