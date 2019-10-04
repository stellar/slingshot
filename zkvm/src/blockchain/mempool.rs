//! In-memory transaction pool for transactions that are not yet in a block.

use crate::utreexo;
use crate::{TxID, VerifiedTx};
use std::mem;

use super::{BlockchainError, BlockchainState, ValidationContext};

/// Implements a pool of unconfirmed (not-in-the-block) transactions.
pub struct Mempool<T: AsRef<VerifiedTx>> {
    state: BlockchainState,
    timestamp_ms: u64,
    validation: ValidationContext,
    items: Vec<(T, Vec<utreexo::Proof>)>,
}

impl<T: AsRef<VerifiedTx>> Mempool<T> {
    /// Creates an empty mempool at a given state.
    pub fn new(state: BlockchainState, timestamp_ms: u64) -> Self {
        let validation =
            ValidationContext::new(state.tip.version, timestamp_ms, state.utreexo.work_forest());
        Mempool {
            state,
            timestamp_ms,
            validation,
            items: Vec::new(),
        }
    }

    /// Returns a list of transactions
    pub fn items(&self) -> impl Iterator<Item = &T> {
        self.items.iter().map(|(t, _)| t)
    }

    /// Returns a list of transactions
    pub fn utxo_proofs(&self) -> impl Iterator<Item = &utreexo::Proof> {
        self.items.iter().flat_map(|(_, proofs)| proofs.iter())
    }

    /// Returns the size of the mempool in number of transactions.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Updates timestamp and re-applies txs to filter out the outdated ones.
    pub fn update_timestamp(&mut self, timestamp_ms: u64) {
        // TBD: refactor the state API to work with VerifiedTx
        // so we don't repeat expensive stateless checks.

        self.timestamp_ms = timestamp_ms;

        let work_forest = self.state.utreexo.work_forest();
        self.validation = ValidationContext::new(self.timestamp_ms, self.timestamp_ms, work_forest);

        let oldtxs = mem::replace(&mut self.items, Vec::new());

        for (tx, proofs) in oldtxs.into_iter() {
            match self.validation.apply_tx(tx.as_ref(), proofs.iter()) {
                Ok(_) => {
                    // put back to mempool
                    self.items.push((tx, proofs));
                }
                Err(_) => {
                    // tx kicked out of the mempool
                }
            }
        }
    }

    /// Adds transaction to the mempool and verifies it.
    pub fn append(
        &mut self,
        tx: T,
        utxo_proofs: Vec<utreexo::Proof>,
    ) -> Result<TxID, BlockchainError> {
        self.validation.apply_tx(tx.as_ref(), utxo_proofs.iter())?;
        let txid = tx.as_ref().id;
        self.items.push((tx, utxo_proofs));
        Ok(txid)
    }
}
