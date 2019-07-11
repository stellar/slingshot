//! "Nonce units", aka "nits" are built-in assets used to provide uniqueness anchors to the ZkVM transactions.
//! Nits have a special all-zero flavor to domain-separate them from all issued assets.
//! Nits are introduced gradually, so they can always be available
//! to new users for mixing into their transactions.
//!
//! Issuance is 1 nit per second, using an exponentially decreasing schedule
//! in order to cap the total amount to fit under u64.
//! 1 millionth of a nit is simply called "micro nit" or "unit".

use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

use crate::{Anchor, Commitment, Contract, PortableItem, Predicate, Value};

/// Interval of halving the amount of issued nits, in ms.
pub const HALVING_INTERVAL: u64 = 4 * 365 * 24 * 3600 * 1000;

/// Number of units issued per ms, before halving.
pub const UNITS_PER_MS: u64 = 1000;

/// Returns amount eligible for circulation between
/// the initial time and the current time, in units.
pub fn circulation(initial_time_ms: u64, current_time_ms: u64) -> u64 {
    if current_time_ms < initial_time_ms {
        return 0;
    }

    let mut interval_ms = current_time_ms - initial_time_ms;
    let mut circulation = 0u64;
    let mut halvings = 0u64;

    while interval_ms > 0 {
        let increment_ms = if interval_ms > HALVING_INTERVAL {
            interval_ms -= HALVING_INTERVAL;
            HALVING_INTERVAL
        } else {
            let tmp = interval_ms;
            interval_ms = 0;
            tmp
        };
        if halvings < 64 {
            circulation += (increment_ms * UNITS_PER_MS) >> halvings;
            halvings += 1;
        }
    }
    circulation
}

/// Returns amount eligible for the block created between
/// the `prev_time_ms` and `new_time_ms`.
pub fn block_allowance(initial_time_ms: u64, prev_time_ms: u64, new_time_ms: u64) -> u64 {
    circulation(initial_time_ms, new_time_ms) - circulation(initial_time_ms, prev_time_ms)
}

/// Creates a new contract with a given quantity of nits.
pub fn make_nit_contract(
    qty: u64,
    predicate: Predicate,
    anchoring_transcript: &mut Transcript,
) -> Contract {
    Contract::new(
        predicate,
        vec![PortableItem::Value(Value {
            qty: Commitment::unblinded(Scalar::from(qty)),
            flv: Commitment::unblinded(Scalar::zero()),
        })],
        Anchor::nit_anchor(anchoring_transcript),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_circulation() {
        assert_eq!(circulation(0, 0), 0);
        assert_eq!(circulation(2, 1), 0);
    }

    #[test]
    fn simple_circulation() {
        assert_eq!(circulation(0, 1), UNITS_PER_MS);
        assert_eq!(circulation(100, 101), UNITS_PER_MS);
    }

    #[test]
    fn halving() {
        assert_eq!(block_allowance(0, 100, 101), UNITS_PER_MS);
        assert_eq!(
            block_allowance(0, HALVING_INTERVAL, HALVING_INTERVAL + 1),
            UNITS_PER_MS / 2
        );
        assert_eq!(
            block_allowance(0, HALVING_INTERVAL + 1, HALVING_INTERVAL + 2),
            UNITS_PER_MS / 2
        );
        assert_eq!(
            block_allowance(0, 2 * HALVING_INTERVAL, 2 * HALVING_INTERVAL + 1),
            UNITS_PER_MS / 4
        );
        assert_eq!(
            block_allowance(0, 3 * HALVING_INTERVAL, 3 * HALVING_INTERVAL + 1),
            UNITS_PER_MS / 8
        );
        assert_eq!(
            block_allowance(0, 4 * HALVING_INTERVAL, 4 * HALVING_INTERVAL + 1),
            UNITS_PER_MS / 16
        );
    }
}
