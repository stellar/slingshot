/// Represents a usize with value in the range [0,64]
pub struct BitRange(usize);

impl BitRange {
    /// Returns BitRange if n is <= 64>
    /// Otherwise Errors
    pub fn new(n: usize) -> Option<Self> {
        if n > 64 {
            None
        } else {
            Some(BitRange(n))
        }
    }

    /// max returns a BitRange
    /// representing a 64-bit usize
    pub fn max() -> Self {
        BitRange(64)
    }
}

impl Into<usize> for BitRange {
    fn into(self) -> usize {
        self.0
    }
}
