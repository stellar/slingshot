/// Represents a usize with value in the range [0,64]
pub struct BitRange(usize);

impl BitRange {
    fn new(n: usize) -> Option<Self> {
        if n > 64 {
            None
        } else {
            Some(BitRange(n))
        }
    }
}

impl Into<usize> for BitRange {
    fn into(self) -> usize {
        self.0
    }
}
