use crate::{mix::k_mix, range_proof};
use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use shuffle::{padded_shuffle, value_shuffle};
use value::AllocatedValue;

/// Enforces that the outputs are a valid rearrangement of the inputs, following the
/// soundness and secrecy requirements in the [Cloak specification](../spec.md).
pub fn cloak<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<AllocatedValue>,
    outputs: Vec<AllocatedValue>,
) -> Result<(), R1CSError> {
    // Merge
    let (merge_in, merge_out) = merge(cs, inputs.clone())?;

    // Split
    let (split_in, split_out) = split(cs, outputs.clone())?;

    // Shuffle 1
    // Check that `merge_in` is a valid reordering of `inputs`
    // when `inputs` are grouped by flavor.
    value_shuffle(cs, inputs, merge_in)?;

    // Shuffle 2
    // Check that `split_in` is a valid reordering of `merge_out`, allowing for
    // the adding or dropping of padding values (quantity = 0) if m != n.
    padded_shuffle(cs, merge_out, split_in)?;

    // Shuffle 3
    // Check that `split_out` is a valid reordering of `outputs`
    // when `outputs` are grouped by flavor.
    value_shuffle(cs, split_out, outputs.clone())?;

    // Range Proof
    // Check that each of the quantities in `outputs` lies in [0, 2^64).
    for output in outputs {
        range_proof(cs, output.q.into(), output.assignment.map(|v| v.q), 64)?;
    }

    Ok(())
}

/// Enforces that the outputs are either a merge of the inputs: `D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for `k` inputs and `k` outputs.
fn merge<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<AllocatedValue>,
) -> Result<(Vec<AllocatedValue>, Vec<AllocatedValue>), R1CSError> {
    k_mix(cs, inputs)
}

/// Enforces that the outputs are either a split of the inputs :`A = C + D && B = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for `k` inputs and `k` outputs.
///
/// Note: the `split` gadget is the same thing as a `merge` gadget, but "backwards".
/// This means that if you reverse all of the commitment vectors, and switch the
/// inputs and outputs of a `merge` gadget, then you have a `split` gadget.
fn split<CS: ConstraintSystem>(
    cs: &mut CS,
    mut inputs: Vec<AllocatedValue>,
) -> Result<(Vec<AllocatedValue>, Vec<AllocatedValue>), R1CSError> {
    inputs.reverse();
    k_mix(cs, inputs).map(|(outs, ins)| (ins, outs))
}
