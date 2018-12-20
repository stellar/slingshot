#![allow(non_snake_case)]

use super::mix;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use curve25519_dalek::scalar::Scalar;
use std::iter::once;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use value::{AllocatedValue, Value};

/// Enforces that the outputs are either a merge of the inputs: `D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for `k` inputs and `k` outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<AllocatedValue>,
) -> Result<(Vec<AllocatedValue>, Vec<AllocatedValue>), R1CSError> {
    // If there is only one input and output, just constrain the input
    // and output to be equal to each other.
    if inputs.len() == 1 {
        let i = inputs[0];
        let o = i.reallocate(cs)?;
        cs.constrain(i.q - o.q);
        cs.constrain(i.a - o.a);
        cs.constrain(i.t - o.t);
        return Ok((vec![i], vec![o]));
    }

    let mix_in = order_by_flavor(&inputs, cs);
    let (mix_mid, mix_out) = mix_helper(&mix_in, cs);

    let first_in = mix_in[0].clone();
    let last_out = mix_out[mix_out.len() - 1].clone();

    // For each 2-mix, constrain A, B, C, D:
    for (((A, B), C), D) in
        // A = (first_in||mix_mid)[i]
        once(first_in).chain(mix_mid.clone().into_iter())
        // B = mix_in[i+1]
        .zip(mix_in.into_iter().skip(1))
        // C = mix_out[i]
        .zip(mix_out.into_iter())
        // D = (mix_mid||last_out)[i]
        .zip(mix_mid.into_iter().chain(once(last_out)))
    {
        mix::fill_cs(cs, A, B, C, D)
    }

    Ok((mix_in, mix_out))
}

// Takes as input a vector of `AllocatedValue`s, returns a vector of `AllocatedValue`s that
// is a reordering of the inputs where all `AllocatedValues` have been grouped according to flavor.
fn order_by_flavor<CS: ConstraintSystem>(
    inputs: &Vec<AllocatedValue>,
    cs: &mut CS,
) -> Vec<AllocatedValue> {
    let collected_inputs: Option<Vec<_>> = inputs.iter().map(|input| input.assignment).collect();
    match collected_inputs {
        Some(input_values) => unimplemented!(),
        None => unimplemented!(),
    }
}

fn shuffle_helper(shuffle_in: &Vec<Value>) -> Vec<Value> {
    let k = shuffle_in.len();
    let mut shuffle_out = shuffle_in.clone();

    for i in 0..k - 1 {
        // This tuple has the flavor that we are trying to group by in this loop
        let flav = shuffle_out[i];
        // This tuple may be swapped with another tuple (`comp`)
        // if `comp` and `flav` have the same flavor.
        let mut swap = shuffle_out[i + 1];

        for j in i + 2..k {
            // Iterate over all following tuples, assigning them to `comp`.
            let mut comp = shuffle_out[j];
            // Check if `flav` and `comp` have the same flavor.
            let same_flavor = flav.a.ct_eq(&comp.a) & flav.t.ct_eq(&comp.t);

            // If same_flavor, then swap `comp` and `swap`. Else, keep the same.
            u64::conditional_swap(&mut swap.q, &mut comp.q, same_flavor);
            Scalar::conditional_swap(&mut swap.a, &mut comp.a, same_flavor);
            Scalar::conditional_swap(&mut swap.t, &mut comp.t, same_flavor);
            shuffle_out[i + 1] = swap;
            shuffle_out[j] = comp;
        }
    }
    shuffle_out
}

// Takes:
// * a vector of `AllocatedValue`s that represents the input values in a k-mix
//
// Returns:
// * a vector of `AllocatedValue`s that represents the intermediate values in a k-mix
// * a vector of `AllocatedValue`s that represents the outputs values of a k-mix
fn mix_helper<CS: ConstraintSystem>(
    inputs: &Vec<AllocatedValue>,
    cs: &mut CS,
) -> (Vec<AllocatedValue>, Vec<AllocatedValue>) {
    unimplemented!();
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::{Prover, Verifier};
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
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
    ) -> Result<(), R1CSError> {
        // Common
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

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
*/
