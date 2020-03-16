//! Mempool
use core::borrow::Borrow;
use core::mem;
use serde::{Deserialize, Serialize};

use crate::utreexo::{self, utreexo_hasher, Catchup, WorkForest};
use zkvm::{ContractID, Hasher, MerkleTree, TxEntry, TxHeader, TxLog, VerifiedTx};

use super::block::BlockHeader;
use super::errors::BlockchainError;
use super::state::BlockchainState;

/// Implements a pool of unconfirmed (not-in-the-block) transactions.
#[derive(Clone, Serialize, Deserialize)]
pub struct Mempool<T: MempoolItem> {
    state: BlockchainState,
    timestamp_ms: u64,
    work_utreexo: utreexo::WorkForest,
    items: Vec<T>,
}

/// Trait for the items in the mempool.
pub trait MempoolItem {
    /// Returns a reference to a verified transaction
    fn verified_tx(&self) -> &VerifiedTx;

    /// Returns a collection of Utreexo proofs for the transaction.
    fn utreexo_proofs(&self) -> &[utreexo::Proof];
}

impl<T: MempoolItem> Mempool<T> {
    /// Creates an empty mempool at a given state.
    pub fn new(state: BlockchainState, timestamp_ms: u64) -> Self {
        let work_utreexo = state.utreexo.work_forest();
        Mempool {
            state,
            timestamp_ms,
            work_utreexo,
            items: Vec::new(),
        }
    }

    /// Returns a list of transactions.
    pub fn items(&self) -> impl Iterator<Item = &T> {
        self.items.iter()
    }

    /// Returns the size of the mempool in number of transactions.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Updates timestamp and re-applies txs to filter out the outdated ones.
    pub fn update_timestamp(&mut self, timestamp_ms: u64) {
        self.timestamp_ms = timestamp_ms;
        self.update_mempool();
    }

    /// Adds transaction to the mempool and verifies it.
    pub fn append(&mut self, item: T) -> Result<(), BlockchainError> {
        self.apply_item(&item)?;
        self.items.push(item);
        Ok(())
    }

    /// Creates a new block header and a new blockchain state using the current set of transactions.
    /// Block header is accesible through the `tip` field on the new `BlockchainState` value.
    pub fn make_block(&self) -> Result<(BlockchainState, Catchup), BlockchainError> {
        let txroot = MerkleTree::root(
            b"ZkVM.txroot",
            self.items.iter().map(|tx| &tx.verified_tx().id),
        );

        let hasher = utreexo_hasher::<ContractID>();
        let (new_forest, new_catchup) = self.work_utreexo.normalize(&hasher);
        let utxoroot = new_forest.root(&hasher);

        let new_header = BlockHeader {
            version: self.state.tip.version,
            height: self.state.tip.height + 1,
            prev: self.state.tip.id(),
            timestamp_ms: self.timestamp_ms,
            txroot,
            utxoroot,
            ext: Vec::new(),
        };

        let new_state = BlockchainState {
            tip: new_header,
            utreexo: new_forest,
        };

        Ok((new_state, new_catchup))
    }

    fn update_mempool(&mut self) {
        // reset the utreexo to the original state
        self.work_utreexo = self.state.utreexo.work_forest();

        // extract old
        let old_items = mem::replace(&mut self.items, Vec::new());

        for item in old_items.into_iter() {
            match self.apply_item(&item) {
                Ok(_) => {
                    // still valid - put back to mempool
                    self.items.push(item);
                }
                Err(_) => {
                    // tx kicked out of the mempool
                }
            }
        }
    }

    fn apply_item(&mut self, item: &T) -> Result<(), BlockchainError> {
        let vtx = item.verified_tx();
        let proofs = item.utreexo_proofs();

        check_tx_header(&vtx.header, self.timestamp_ms, self.state.tip.version)?;

        // Update block makes sure the that if half of tx fails, all changes are undone.
        self.work_utreexo
            .batch(|wf| apply_tx(wf, &vtx.log, proofs.iter(), &utreexo_hasher()))
            .map(|_| ())
    }
}

/// Applies transaction to the Utreexo forest
fn apply_tx<P>(
    work_forest: &mut WorkForest,
    txlog: &TxLog,
    utxo_proofs: impl IntoIterator<Item = P>,
    hasher: &Hasher<ContractID>,
) -> Result<(), BlockchainError>
where
    P: Borrow<utreexo::Proof>,
{
    let mut utxo_proofs = utxo_proofs.into_iter();

    for entry in txlog.iter() {
        match entry {
            // Remove item from the UTXO set
            TxEntry::Input(contract_id) => {
                let proof = utxo_proofs
                    .next()
                    .ok_or(BlockchainError::UtreexoProofMissing)?;

                work_forest
                    .delete(contract_id, proof.borrow(), &hasher)
                    .map_err(|e| BlockchainError::UtreexoError(e))?;
            }
            // Add item to the UTXO set
            TxEntry::Output(contract) => {
                work_forest.insert(&contract.id(), &hasher);
            }
            // Ignore all other log items
            _ => {}
        }
    }

    Ok(())
}

/// Checks the tx header for consistency with the block header.
fn check_tx_header(
    tx_header: &TxHeader,
    timestamp_ms: u64,
    block_version: u64,
) -> Result<(), BlockchainError> {
    check(
        timestamp_ms >= tx_header.mintime_ms,
        BlockchainError::BadTxTimestamp,
    )?;
    check(
        timestamp_ms <= tx_header.maxtime_ms,
        BlockchainError::BadTxTimestamp,
    )?;
    if block_version == 1 {
        check(tx_header.version == 1, BlockchainError::BadTxVersion)?;
    } else {
        // future block versions permit higher tx versions
    }
    Ok(())
}

#[inline]
fn check<E>(cond: bool, err: E) -> Result<(), E> {
    if !cond {
        return Err(err);
    }
    Ok(())
}
