use bulletproofs::r1cs::ConstraintSystem;
use error::SpacesuitError;
use gadgets::{merge, padded_shuffle, range_proof, split, value::Value, value_shuffle};
use std::cmp::max;

/// Enforces that the outputs are a valid rearrangement of the inputs, following the
/// soundness and secrecy requirements in the spacesuit transaction spec:
/// https://github.com/interstellar/spacesuit/blob/master/spec.md
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    merge_in: Vec<Value>,
    merge_mid: Vec<Value>,
    merge_out: Vec<Value>,
    split_in: Vec<Value>,
    split_mid: Vec<Value>,
    split_out: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
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
        return Err(SpacesuitError::InvalidR1CSConstruction);
    }

    // Shuffle 1
    // Check that `merge_in` is a valid reordering of `inputs`
    // when `inputs` are grouped by flavor.
    value_shuffle::fill_cs(cs, inputs, merge_in.clone())?;

    // Merge
    // Check that `merge_out` is a valid combination of `merge_in`,
    // when all values of the same flavor in `merge_in` are combined.
    merge::fill_cs(cs, merge_in, merge_mid, merge_out.clone())?;

    // Shuffle 2
    // Check that `split_in` is a valid reordering of `merge_out`, allowing for
    // the adding or dropping of padding values (quantity = 0) if m != n.
    padded_shuffle::fill_cs(cs, merge_out, split_in.clone())?;

    // Split
    // Check that `split_in` is a valid combination of `split_out`,
    // when all values of the same flavor in `split_out` are combined.
    split::fill_cs(cs, split_in, split_mid, split_out.clone())?;

    // Shuffle 3
    // Check that `split_out` is a valid reordering of `outputs`
    // when `outputs` are grouped by flavor.
    value_shuffle::fill_cs(cs, split_out, outputs.clone())?;

    // Range Proof
    // Check that each of the quantities in `outputs` lies in [0, 2^64).
    for output in outputs {
        range_proof::fill_cs(cs, output.q, 64)?;
    }

    Ok(())
}
