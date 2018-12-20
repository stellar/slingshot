use super::k_mix;
use bulletproofs::r1cs::{ConstraintSystem, R1CSError};
use value::AllocatedValue;

/// Enforces that the outputs are either a split of the inputs :`A = C + D && B = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for `k` inputs and `k` outputs.
///
/// Note: the `split` gadget is the same thing as a `merge` gadget, but "backwards".
/// This means that if you reverse all of the commitment vectors, and switch the
/// inputs and outputs of a `merge` gadget, then you have a `split` gadget.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    mut inputs: Vec<AllocatedValue>,
) -> Result<(Vec<AllocatedValue>, Vec<AllocatedValue>), R1CSError> {
    inputs.reverse();
    k_mix::fill_cs(cs, inputs)
}
