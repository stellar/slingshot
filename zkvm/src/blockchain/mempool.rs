//! In-memory transaction pool for transactions that are not yet in a block.

use crate::encoding::Encodable;
use crate::utreexo;
use crate::{Tx, TxID, VerifiedTx};
use bulletproofs::BulletproofGens;
use std::mem;

use super::{BlockchainError, BlockchainState, ValidationContext};

/// Implements a pool of unconfirmed (not-in-the-block) transactions.
pub struct Mempool {
    state: BlockchainState,
    timestamp_ms: u64,
    validation: ValidationContext,
    txs: Vec<(Tx, VerifiedTx, Vec<utreexo::Proof>)>,
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

    /// Estimated cost of a memory occupied by transactions in the mempool.
    pub fn estimated_memory_cost(&self) -> usize {
        self.txs
            .iter()
            .map(|(tx, _, proofs)| {
                tx.serialized_length() + proofs.iter().map(|p| p.serialized_length()).sum::<usize>()
            })
            .sum()
    }

    /// Returns a list of transactions
    pub fn txs(&self) -> impl Iterator<Item = &Tx> {
        self.txs.iter().map(|(tx, _, _)| tx)
    }

    /// Returns the size of the mempool in number of transactions.
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    /// Clears mempool.
    pub fn reset(&mut self) {
        let work_forest = self.state.utreexo.work_forest();
        self.validation = ValidationContext::new(self.timestamp_ms, self.timestamp_ms, work_forest);
        self.txs.clear();
    }

    /// Updates timestamp and re-applies txs to filter out the outdated ones.
    pub fn update_timestamp(&mut self, timestamp_ms: u64, bp_gens: &BulletproofGens) {
        // TBD: refactor the state API to work with VerifiedTx
        // so we don't repeat expensive stateless checks.

        self.timestamp_ms = timestamp_ms;

        let work_forest = self.state.utreexo.work_forest();
        self.validation = ValidationContext::new(self.timestamp_ms, self.timestamp_ms, work_forest);

        let oldtxs = mem::replace(&mut self.txs, Vec::new());

        for (tx, _vtx, proofs) in oldtxs.into_iter() {
            match self.append(tx, proofs, bp_gens) {
                Ok(_) => {}
                Err(_) => {
                    // tx kicked out of the mempool
                }
            }
        }
    }

    /// Adds transaction to the mempool and verifies it.
    pub fn append(
        &mut self,
        tx: Tx,
        utxo_proofs: Vec<utreexo::Proof>,
        bp_gens: &BulletproofGens,
    ) -> Result<TxID, BlockchainError> {
        let verified_tx = self.validation.apply_tx(&tx, utxo_proofs.iter(), bp_gens)?;
        let txid = verified_tx.id;
        self.txs.push((tx, verified_tx, utxo_proofs));
        Ok(txid)
    }
}
