#![allow(non_snake_case)]

use bulletproofs::r1cs::{Assignment, ConstraintSystem, Variable};
use curve25519_dalek::scalar::Scalar;
use subtle::{ConditionallySelectable, ConstantTimeEq};
use util::{Value, SpacesuitError};

pub struct KSplitGadget {}

impl KSplitGadget {
    pub fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        inputs: Vec<Value>,
        outputs: Vec<Value>,
    ) -> Result<(), SpacesuitError> {
        inputs.clone().reverse();
        outputs.clone().reverse();
        KMergeGadget::fill_cs(cs, outputs, inputs)
    }
}