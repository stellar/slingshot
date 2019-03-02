use bulletproofs::r1cs::R1CSError;
/// Represents a usize with value in the range [0,64]
pub struct BitRange(usize);

impl BitRange {
    pub fn new(n: usize) -> Result<Self,Err> {
        if n > 64 {
            Err("Invalid Bitrange value. Value must be less than 64")
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
