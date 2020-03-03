use core::borrow::Borrow;
use core::mem;
use serde::{Deserialize, Serialize};

use super::block::{BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::merkle::{Hasher, MerkleTree};
use crate::utreexo::{self, utreexo_hasher, Catchup, Forest, WorkForest};
use crate::{ContractID, TxEntry, TxHeader, TxLog, VerifiedTx};

/// State of the blockchain node.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlockchainState {
    /// Initial block of the given network.
    pub initial_id: BlockID,
    /// Latest block header in the chain.
    pub tip: BlockHeader,
    /// The utreexo state.
    pub utreexo: Forest,
    /// The catchup structure to auto-update the proofs made against the previous state.
    pub catchup: Catchup,
}

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

impl BlockchainState {
    /// Creates an initial block with a given starting set of utxos.
    pub fn make_initial<I>(timestamp_ms: u64, utxos: I) -> (BlockchainState, Vec<utreexo::Proof>)
    where
        I: IntoIterator<Item = ContractID> + Clone,
    {
        let hasher = utreexo_hasher();
        let (utreexo, catchup) = {
            let mut wf = Forest::new().work_forest();
            for utxo in utxos.clone() {
                wf.insert(&utxo, &hasher);
            }
            wf.normalize(&hasher)
        };

        let proofs =
            utxos
                .into_iter()
                .map(|utxo| {
                    catchup.update_proof(&utxo, utreexo::Proof::Transient, &hasher).expect(
                    "Updating proofs should never fail here because we have just created them.",
                )
                })
                .collect::<Vec<_>>();

        let tip = BlockHeader::make_initial(timestamp_ms, utreexo.root(&hasher));
        let state = BlockchainState {
            initial_id: tip.id(),
            tip,
            utreexo,
            catchup,
        };

        (state, proofs)
    }

    /// Applies the block to the current state and returns a new one.
    pub fn apply_block<'t, P>(
        &self,
        block_header: BlockHeader,
        verified_txs: impl IntoIterator<Item = &'t VerifiedTx>,
        utxo_proofs: impl IntoIterator<Item = P>,
    ) -> Result<BlockchainState, BlockchainError>
    where
        P: Borrow<utreexo::Proof>,
    {
        check_block_header(&block_header, &self.tip)?;

        let mut work_forest = self.utreexo.work_forest();
        let mut utxo_proofs = utxo_proofs.into_iter();
        let utxo_hasher = utreexo_hasher::<ContractID>();
        let mut txroot_builder = MerkleTree::build_root(b"ZkVM.txroot");
        for vtx in verified_txs.into_iter() {
            // Check that tx header is consistent with the version / timestamp.
            check_tx_header(&vtx.header, block_header.timestamp_ms, block_header.version)?;

            // Compute the commitment to all txs in a block.
            txroot_builder.append(&vtx.id);

            // Apply tx to the state
            apply_tx(&mut work_forest, &vtx.log, &mut utxo_proofs, &utxo_hasher)?;
        }
        let txroot = txroot_builder.root();
        let (new_forest, new_catchup) = work_forest.normalize(&utxo_hasher);
        let utxoroot = new_forest.root(&utxo_hasher);

        // Check the txroot commitment
        if block_header.txroot != txroot {
            return Err(BlockchainError::InconsistentHeader);
        }

        // Check the utxo set commitment
        if block_header.utxoroot != utxoroot {
            return Err(BlockchainError::InconsistentHeader);
        }

        let new_state = BlockchainState {
            initial_id: self.initial_id,
            tip: block_header,
            utreexo: new_forest,
            catchup: new_catchup,
        };

        Ok(new_state)
    }
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
    pub fn make_block(&self) -> Result<BlockchainState, BlockchainError> {
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
            initial_id: self.state.initial_id,
            tip: new_header,
            utreexo: new_forest,
            catchup: new_catchup,
        };

        Ok(new_state)
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
pub fn check_tx_header(
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

/// Verifies block header with respect to the previous header.
fn check_block_header(
    block_header: &BlockHeader,
    prev_header: &BlockHeader,
) -> Result<(), BlockchainError> {
    check(
        block_header.version >= prev_header.version,
        BlockchainError::InconsistentHeader,
    )?;
    if block_header.version == 1 {
        check(
            block_header.ext.len() == 0,
            BlockchainError::IllegalExtension,
        )?;
    }
    check(
        block_header.height == prev_header.height + 1,
        BlockchainError::InconsistentHeader,
    )?;
    check(
        block_header.timestamp_ms > prev_header.timestamp_ms,
        BlockchainError::InconsistentHeader,
    )?;
    check(
        block_header.prev == prev_header.id(),
        BlockchainError::InconsistentHeader,
    )?;
    Ok(())
}

#[inline]
fn check<E>(cond: bool, err: E) -> Result<(), E> {
    if !cond {
        return Err(err);
    }
    Ok(())
}
