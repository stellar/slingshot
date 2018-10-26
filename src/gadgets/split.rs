use super::k_mix;
use bulletproofs::r1cs::ConstraintSystem;
use util::{SpacesuitError, Value};

/// Enforces that the outputs are either a split of the inputs :`A = C + D && B = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`.
/// Works for `k` inputs and `k` outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    intermediates: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
    let mut inputs_rev = inputs.clone();
    inputs_rev.reverse();
    let mut intermediates_rev = intermediates.clone();
    intermediates_rev.reverse();
    let mut outputs_rev = outputs.clone();
    outputs_rev.reverse();
    k_mix::fill_cs(cs, outputs_rev, intermediates_rev, inputs_rev)
}
