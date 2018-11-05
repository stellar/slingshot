use super::k_mix;
use bulletproofs::r1cs::ConstraintSystem;
use error::SpacesuitError;
use value::Value;

/// Enforces that the outputs are either a merge of the inputs: `D = A + B && C = 0`,
/// or the outputs are equal to the inputs `C = A && D = B`. See spec for more details.
/// Works for `k` inputs and `k` outputs.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    intermediates: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
    k_mix::fill_cs(cs, inputs, intermediates, outputs)
}
