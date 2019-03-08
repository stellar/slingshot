/// Represents a usize with value in the range [0,64]
#[derive(Copy, Clone, Debug)]
pub struct BitRange(usize);

impl BitRange {
    /// Returns Some(BitRange) if `n` is ≤ 64.
    /// Otherwise returns None.
    pub fn new(n: usize) -> Option<Self> {
        if n > 64 {
            None
        } else {
            Some(BitRange(n))
        }
    }

    /// Returns 64-bit range
    pub fn max() -> Self {
        BitRange(64)
    }
}

impl Into<usize> for BitRange {
    fn into(self) -> usize {
        self.0
    }
}

impl Into<u8> for BitRange {
    fn into(self) -> u8 {
        self.0 as u8
    }
}
