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

    let (mix_in, mix_mid, mix_out) = make_intermediate_values(&inputs, cs)?;

    let first_in = mix_in[0].clone();
    let last_out = mix_out[mix_out.len() - 1].clone();

    // For each 2-mix, constrain A, B, C, D:
    for (((A, B), C), D) in
        // A = (first_in||mix_mid)[i]
        once(&first_in).chain(mix_mid.iter())
        // B = mix_in[i+1]
        .zip(mix_in.iter().skip(1))
        // C = mix_out[i]
        .zip(mix_out.iter())
        // D = (mix_mid||last_out)[i]
        .zip(mix_mid.iter().chain(once(&last_out)))
    {
        mix::fill_cs(cs, *A, *B, *C, *D)?
    }

    Ok((mix_in, mix_out))
}

// Takes:
// * a vector of `AllocatedValue`s that represents the input (or output) values for a cloak gadget
//
// Returns:
// * a vector of `AllocatedValue`s for the input values of a k-mix gadget
// * a vector of `AllocatedValue`s for the middle values of a k-mix gadget
// * a vector of `AllocatedValue`s for the output values of a k-mix gadget
fn make_intermediate_values<CS: ConstraintSystem>(
    inputs: &Vec<AllocatedValue>,
    cs: &mut CS,
) -> Result<
    (
        Vec<AllocatedValue>,
        Vec<AllocatedValue>,
        Vec<AllocatedValue>,
    ),
    R1CSError,
> {
    let collected_inputs: Option<Vec<_>> = inputs.iter().map(|input| input.assignment).collect();
    match collected_inputs {
        Some(input_values) => {
            let (mix_in, mix_in_values) = order_by_flavor(&input_values, cs)?;
            let (mix_mid, mix_out) = combine_by_flavor(&mix_in_values, cs)?;
            Ok((mix_in, mix_mid, mix_out))
        }
        None => unimplemented!(),
    }
}

// Takes:
// * a vector of `AllocatedValue`s
//
// Returns:
// * a vector of `AllocatedValue`s that is a reordering of the inputs
//   where all `AllocatedValues` have been grouped according to flavor
// * a vector of `Value`s that were used to create the output `AllocatedValue`s
fn order_by_flavor<CS: ConstraintSystem>(
    inputs: &Vec<Value>,
    cs: &mut CS,
) -> Result<(Vec<AllocatedValue>, Vec<Value>), R1CSError> {
    let k = inputs.len();
    let mut outputs = inputs.clone();

    for i in 0..k - 1 {
        // This tuple has the flavor that we are trying to group by in this loop
        let flav = outputs[i];
        // This tuple may be swapped with another tuple (`comp`)
        // if `comp` and `flav` have the same flavor.
        let mut swap = outputs[i + 1];

        for j in i + 2..k {
            // Iterate over all following tuples, assigning them to `comp`.
            let mut comp = outputs[j];
            // Check if `flav` and `comp` have the same flavor.
            let same_flavor = flav.a.ct_eq(&comp.a) & flav.t.ct_eq(&comp.t);

            // If same_flavor, then swap `comp` and `swap`. Else, keep the same.
            u64::conditional_swap(&mut swap.q, &mut comp.q, same_flavor);
            Scalar::conditional_swap(&mut swap.a, &mut comp.a, same_flavor);
            Scalar::conditional_swap(&mut swap.t, &mut comp.t, same_flavor);
            outputs[i + 1] = swap;
            outputs[j] = comp;
        }
    }

    let allocated_outputs = outputs
        .iter()
        .map(|value| value.allocate(cs))
        .collect::<Result<Vec<AllocatedValue>, _>>()?;

    Ok((allocated_outputs, outputs))
}

// Takes:
// * a vector of `Value`s that are grouped according to flavor
//
// Returns:
// * a vector of the `AllocatedValue`s that are both outputs and inputs to 2-mix gadgets,
//   where `Value`s of the same flavor are combined and `Value`s of different flavors
//   are moved without modification. (See `mix.rs` for more information on 2-mix gadgets.)
// * a vector of the `AllocatedValue`s that are only outputs of 2-mix gadgets.
fn combine_by_flavor<CS: ConstraintSystem>(
    _inputs: &Vec<Value>,
    _cs: &mut CS,
) -> Result<(Vec<AllocatedValue>, Vec<AllocatedValue>), R1CSError> {
    unimplemented!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use bulletproofs::r1cs::Prover;
    use bulletproofs::{BulletproofGens, PedersenGens};
    use merlin::Transcript;
    use value::Value;

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

    // Note: the output vectors for order_by_flavor does not have to be in a particular order,
    // they just has to be grouped by flavor. Thus, it is possible to make a valid change to
    // order_by_flavor but break the tests.
    #[test]
    fn order_by_flavor_test() {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);
        let mut transcript = Transcript::new(b"OrderByFlavorTest");
        let mut prover_cs = Prover::new(&bp_gens, &pc_gens, &mut transcript);

        // k = 1
        assert_eq!(
            order_by_flavor(&vec![yuan(1)], &mut prover_cs).unwrap().1,
            vec![yuan(1)]
        );
        // k = 2
        assert_eq!(
            order_by_flavor(&vec![yuan(1), yuan(2)], &mut prover_cs)
                .unwrap()
                .1,
            vec![yuan(1), yuan(2)]
        );
        assert_eq!(
            order_by_flavor(&vec![yuan(1), peso(2)], &mut prover_cs)
                .unwrap()
                .1,
            vec![yuan(1), peso(2)]
        );
        // k = 3
        assert_eq!(
            order_by_flavor(&vec![yuan(1), peso(3), yuan(2)], &mut prover_cs)
                .unwrap()
                .1,
            vec![yuan(1), yuan(2), peso(3)]
        );
        // k = 4
        assert_eq!(
            order_by_flavor(&vec![yuan(1), peso(3), yuan(2), peso(4)], &mut prover_cs)
                .unwrap()
                .1,
            vec![yuan(1), yuan(2), peso(3), peso(4)]
        );
        assert_eq!(
            order_by_flavor(&vec![yuan(1), peso(3), peso(4), yuan(2)], &mut prover_cs)
                .unwrap()
                .1,
            vec![yuan(1), yuan(2), peso(4), peso(3)]
        );
        assert_eq!(
            order_by_flavor(&vec![yuan(1), peso(3), zero(), yuan(2)], &mut prover_cs)
                .unwrap()
                .1,
            vec![yuan(1), yuan(2), zero(), peso(3)]
        );
        assert_eq!(
            order_by_flavor(&vec![yuan(1), yuan(2), yuan(3), yuan(4)], &mut prover_cs)
                .unwrap()
                .1,
            vec![yuan(1), yuan(4), yuan(3), yuan(2)]
        );
        // k = 5
        assert_eq!(
            order_by_flavor(
                &vec![yuan(1), yuan(2), yuan(3), yuan(4), yuan(5)],
                &mut prover_cs
            )
            .unwrap()
            .1,
            vec![yuan(1), yuan(5), yuan(4), yuan(3), yuan(2)]
        );
        assert_eq!(
            order_by_flavor(
                &vec![yuan(1), peso(2), yuan(3), peso(4), yuan(5)],
                &mut prover_cs
            )
            .unwrap()
            .1,
            vec![yuan(1), yuan(5), yuan(3), peso(4), peso(2)]
        );
        assert_eq!(
            order_by_flavor(
                &vec![yuan(1), peso(2), zero(), peso(4), yuan(5)],
                &mut prover_cs
            )
            .unwrap()
            .1,
            vec![yuan(1), yuan(5), zero(), peso(4), peso(2)]
        );
    }
}
