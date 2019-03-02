use bulletproofs::r1cs::R1CSError;
/// Represents a usize with value in the range [0,64]
pub struct BitRange(usize);

impl BitRange {
    /// Returns BitRange if n is <= 64>
    /// Otherwise Errors
    pub fn new(n: usize) -> Result<Self, R1CSError> {
        if n > 64 {
            Err(R1CSError::GadgetError {
                description: "Invalid Bitrange value. Value must be less than 64".to_string(),
            })
        } else {
            Ok(BitRange(n))
        }
    }
}

impl Into<usize> for BitRange {
    fn into(self) -> usize {
        self.0
    }
}
