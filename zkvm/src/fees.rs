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
#[derive(Copy, Clone, Default, Debug, Serialize, Deserialize)]
pub struct FeeRate {
    fee: u64,
    size: u64,
}

/// Flavor of the asset used to pay the fees.
pub fn fee_flavor() -> Scalar {
    Scalar::zero()
}

impl FeeRate {
    /// Creates a new zero feerate
    pub fn zero() -> Self {
        FeeRate::default()
    }

    /// Creates a new fee rate from a given fee and size.
    pub fn new(fee: CheckedFee, size: usize) -> Self {
        FeeRate {
            fee: fee.inner,
            size: size as u64,
        }
    }

    /// Combines the fee rate with another fee rate, adding up the fees and sizes.
    pub fn combine(self, other: FeeRate) -> Self {
        FeeRate {
            fee: self.fee + other.fee,
            size: self.size + other.size,
        }
    }

    /// Converts the fee rate to a floating point number.
    pub fn to_f64(self) -> f64 {
        (self.fee as f64) / (self.size as f64)
    }

    /// Normalizes feerate by dividing the fee by size rounding it down.
    /// Yields a fee amount per 1 byte of size.
    pub fn normalize(mut self) -> Self {
        self.fee /= self.size;
        self.size = 1;
        self
    }

    /// Increases the feerate by the given feerate, without changing the underlying size.
    /// (Meaning the feerate added in normalized form, as amount of fee per 1 byte.)
    pub fn increase_by(mut self, other: Self) -> Self {
        self.fee += (other.fee * self.size) / other.size;
        self
    }

    /// Multiplies the feerate and returns a normalized feerate (with size=1).
    pub fn mul(mut self, f: f64) -> Self {
        self.fee = ((self.fee as f64 * f) / self.size as f64).round() as u64;
        self.size = 1;
        self
    }

    /// Discounts the fee and the size by a given factor.
    /// E.g. feerate 100/1200 discounted by 2 gives 50/600.
    /// Same ratio, but lower weight when combined with other feerates.
    pub fn discount(mut self, parts: usize) -> Self {
        let parts = parts as u64;
        self.fee /= parts;
        self.size /= parts;
        self
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
