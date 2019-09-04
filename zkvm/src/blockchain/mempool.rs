//! In-memory transaction pool for transactions that are not yet in a block.

use crate::utreexo;
use crate::{Tx, TxID, VerifiedTx};
use bulletproofs::BulletproofGens;
use core::borrow::Borrow;

use super::{BlockchainError, BlockchainState, ValidationContext};

/// Implements a pool of unconfirmed (not-in-the-block) transactions.
pub struct Mempool {
    state: BlockchainState,
    timestamp_ms: u64,
    validation: ValidationContext,
    txs: Vec<(Tx, VerifiedTx)>,
}

impl Mempool {
    /// Creates an empty mempool at a given state.
    pub fn new(state: BlockchainState, timestamp_ms: u64) -> Self {
        let validation =
            ValidationContext::new(state.tip.version, timestamp_ms, state.utreexo.work_forest());
        Mempool {
            state,
            timestamp_ms,
            validation,
            txs: Vec::new(),
        }
    }

    /// Clears mempool
    pub fn reset(&mut self) {
        let work_forest = self.state.utreexo.work_forest();
        self.validation = ValidationContext::new(self.timestamp_ms, self.timestamp_ms, work_forest);
        self.txs.clear();
    }

    /// Adds transaction to the mempool and verifies it.
    pub fn append<P: Borrow<utreexo::Proof>>(
        &mut self,
        tx: Tx,
        utxo_proofs: impl IntoIterator<Item = Option<P>>,
        bp_gens: &BulletproofGens,
    ) -> Result<TxID, BlockchainError> {
        let verified_tx = self
            .validation
            .apply_tx(&tx, utxo_proofs.into_iter(), bp_gens)?;
        let txid = verified_tx.id;
        self.txs.push((tx, verified_tx));
        Ok(txid)
    }
}
