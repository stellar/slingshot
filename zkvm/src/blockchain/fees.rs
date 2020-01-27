//! Fee mechanism.
use core::cmp::Ordering;

/// Maximum amount of fee, which allows overflow-safe size-by-fee multiplication.
pub const MAX_FEE: u64 = 1 << 24;
/// Maximum size of transaction which allows overflow-safe size-by-fee multiplication.
pub const MAX_SIZE: u64 = 1 << 24;

/// Fee rate is a ratio of the transaction fee to its size.
#[derive(Copy, Clone, Debug)]
pub struct FeeRate {
    fee: u64,
    size: u64,
}

impl FeeRate {
    /// Creates a new fee rate from a given fee and size.
    pub fn new(fee: u64, size: usize) -> Option<Self> {
        let size = size as u64;
        if fee > MAX_FEE {
            return None;
        }
        if size > MAX_SIZE {
            return None;
        }
        Some(FeeRate {
            fee,
            size: size as u64,
        })
    }

    /// Combines the fee rate with another fee rate, adding up the fees and sizes.
    pub fn combine(&self, other: FeeRate) -> Self {
        FeeRate {
            fee: self.fee + other.fee,
            size: self.size + other.size,
        }
    }

    /// Converts the fee rate to a floating point number.
    pub fn to_f64(&self) -> f64 {
        (self.fee as f64) / (self.size as f64)
    }

    /// Returns the fee component of the feerate.
    pub fn fee(&self) -> u64 {
        self.fee
    }

    /// Returns the size component of the feerate.
    pub fn size(&self) -> usize {
        self.size as usize
    }
}

impl PartialEq for FeeRate {
    fn eq(&self, other: &Self) -> bool {
        self.fee * other.size == self.size * other.fee
    }
}
impl Eq for FeeRate {}

impl Ord for FeeRate {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.fee * other.size).cmp(&(self.size * other.fee))
    }
}

impl PartialOrd for FeeRate {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
