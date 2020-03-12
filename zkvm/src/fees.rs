//! Fee mechanism.
use core::cmp::Ordering;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};

/// Maximum amount of fee, which allows overflow-safe size-by-fee multiplication.
pub const MAX_FEE: u64 = 1 << 24;

/// Fee checked to be less or equal to `MAX_FEE`.
#[derive(Copy, Clone, Debug)]
pub struct CheckedFee {
    inner: u64,
}

/// Fee rate is a ratio of the transaction fee to its size.
#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
pub struct FeeRate {
    fee: u64,
    size: u64,
}

/// Flavor of the asset used to pay the fees.
pub fn fee_flavor() -> Scalar {
    Scalar::zero()
}

impl FeeRate {
    /// Creates a new fee rate from a given fee and size.
    pub fn new(fee: CheckedFee, size: usize) -> Self {
        FeeRate {
            fee: fee.inner,
            size: size as u64,
        }
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

impl CheckedFee {
    /// Creates a zero fee.
    pub const fn zero() -> Self {
        CheckedFee { inner: 0 }
    }

    /// Creates a fee checked to be ≤ `MAX_FEE`.
    pub fn new(fee: u64) -> Option<Self> {
        CheckedFee::zero().add(fee)
    }

    /// Adds a fee and checks the result for being within `MAX_FEE`.
    pub fn add(mut self, fee: u64) -> Option<Self> {
        if fee > MAX_FEE {
            return None;
        }
        if self.inner + fee > MAX_FEE {
            return None;
        }
        self.inner += fee;
        Some(self)
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
