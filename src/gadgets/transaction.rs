use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use gadgets::{merge, padded_shuffle, range_proof, split, value_shuffle};
use std::cmp::max;
use value::AllocatedValue;

/// Enforces that the outputs are a valid rearrangement of the inputs, following the
/// soundness and secrecy requirements in the spacesuit transaction spec:
/// https://github.com/interstellar/spacesuit/blob/master/spec.md
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<AllocatedValue>,
    merge_in: Vec<AllocatedValue>,
    merge_mid: Vec<AllocatedValue>,
    merge_out: Vec<AllocatedValue>,
    split_in: Vec<AllocatedValue>,
    split_mid: Vec<AllocatedValue>,
    split_out: Vec<AllocatedValue>,
    outputs: Vec<AllocatedValue>,
) -> Result<(), R1CSError> {
    let m = inputs.len();
    let n = outputs.len();
    let inner_merge_count = max(m, 2) - 2; // max(m - 2, 0)
    let inner_split_count = max(n, 2) - 2; // max(n - 2, 0)
    if inputs.len() != merge_in.len()
        || merge_in.len() != merge_out.len()
        || split_in.len() != split_out.len()
        || split_out.len() != outputs.len()
        || merge_mid.len() != inner_merge_count
        || split_mid.len() != inner_split_count
    {
        return Err(R1CSError::GadgetError {
            description: "vector lengths do not match in transaction gadget".to_string(),
        });
    }

    // Merge
    // Check that `merge_out` is a valid combination of `merge_in`,
    // when all values of the same flavor in `merge_in` are combined.
    let (merge_in, merge_out) = merge::fill_cs(cs, inputs.clone())?;

    // Split
    // Check that `split_in` is a valid combination of `split_out`,
    // when all values of the same flavor in `split_out` are combined.
    let (split_out, split_in) = split::fill_cs(cs, outputs.clone())?;

    // Shuffle 1
    // Check that `merge_in` is a valid reordering of `inputs`
    // when `inputs` are grouped by flavor.
    value_shuffle::fill_cs(cs, inputs, merge_in)?;

    // Shuffle 2
    // Check that `split_in` is a valid reordering of `merge_out`, allowing for
    // the adding or dropping of padding values (quantity = 0) if m != n.
    padded_shuffle::fill_cs(cs, merge_out, split_in)?;

    // Shuffle 3
    // Check that `split_out` is a valid reordering of `outputs`
    // when `outputs` are grouped by flavor.
    value_shuffle::fill_cs(cs, split_out, outputs.clone())?;

    // Range Proof
    // Check that each of the quantities in `outputs` lies in [0, 2^64).
    for output in outputs {
        range_proof::fill_cs(cs, output.quantity(), 64)?;
    }

    Ok(())
}
