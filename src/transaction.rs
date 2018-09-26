// use gadgets::{KMergeGadget, KValueShuffleGadget, KSplitGadget, RangeProofGadget, PadGadget};
use bulletproofs::circuit_proof::ConstraintSystem;
use bulletproofs::R1CSError;
use util::Value;

pub struct TransactionGadget {}

impl TransactionGadget {
    fn fill_cs<CS: ConstraintSystem>(
        cs: &mut CS,
        inputs: Vec<Value>,
        outputs: Vec<Value>,
    ) -> Result<(), R1CSError> {
        unimplemented!();
    }
}
