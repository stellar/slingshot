use gadgets::{k_merge, k_split, k_value_shuffle, pad, range_proof};
use bulletproofs::r1cs::{Assignment, ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use util::{SpacesuitError, Value};

// Enforces that the outputs are a valid rearrangement of the inputs, following the 
// soundness and secrecy requirements in the spacesuit spec.
pub fn fill_cs<CS: ConstraintSystem>(
    cs: &mut CS,
    inputs: Vec<Value>,
    outputs: Vec<Value>,
) -> Result<(), SpacesuitError> {
    unimplemented!();
}
