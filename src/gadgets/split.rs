use super::mix;
use bulletproofs::r1cs::ConstraintSystem;
use util::{SpacesuitError, Value};

pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
    inputs.clone().reverse();
    outputs.clone().reverse();
    mix::fill_cs(cs, outputs, inputs)
}
