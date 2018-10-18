#![allow(non_snake_case)]

use bulletproofs::r1cs::{Assignment, ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use util::{Value, SpacesuitError};

pub struct KMergeGadget {}

impl KMergeGadget {
    pub fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        inputs: Vec<Value>,
        outputs: Vec<Value>,
    ) -> Result<(), SpacesuitError> {
        KMixGadget::fill_cs(cs, inputs, outputs)
    }
}
