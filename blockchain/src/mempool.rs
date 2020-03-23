//! Super-simple mempool implementation.
use core::mem;
use serde::{Deserialize, Serialize};

use zkvm::bulletproofs::BulletproofGens;
use zkvm::{ContractID, MerkleTree, Tx, TxEntry, TxID, TxLog, VerifiedTx};

use super::block::{BlockHeader, BlockTx};
use super::errors::BlockchainError;
use super::state::{check_tx_header, BlockchainState};
use super::utreexo::{self, utreexo_hasher, Catchup};

/// Implements a pool of unconfirmed (not-in-the-block) transactions.
#[derive(Clone, Serialize, Deserialize)]
pub struct Mempool {
    state: BlockchainState,
    timestamp_ms: u64,
    work_utreexo: utreexo::WorkForest,
    entries: Vec<MempoolEntry>,
}

/// Tx item stored in the mempool
#[derive(Clone, Serialize, Deserialize)]
pub struct MempoolEntry {
    block_tx: BlockTx,
    verified_tx: VerifiedTx,
}

impl MempoolEntry {
    /// Returns transaction log.
    pub fn txlog(&self) -> &TxLog {
        &self.verified_tx.log
    }

    /// Returns transaction ID.
    pub fn txid(&self) -> TxID {
        self.verified_tx.id
    }

    /// Returns the block tx.
    pub fn block_tx(&self) -> &BlockTx {
        &self.block_tx
    }

    /// Returns the raw VM tx.
    pub fn tx(&self) -> &Tx {
        &self.block_tx.tx
    }

    /// Returns the verified transaction.
    pub fn verified_tx(&self) -> &VerifiedTx {
        &self.verified_tx
    }

    /// Returns the verified transaction.
    pub fn utxo_proofs(&self) -> &[utreexo::Proof] {
        &self.block_tx.proofs
    }
}

impl Mempool {
    /// Creates an empty mempool at a given state.
    pub fn new(state: BlockchainState, timestamp_ms: u64) -> Self {
        let work_utreexo = state.utreexo.work_forest();
        Mempool {
            state,
            timestamp_ms,
            work_utreexo,
            entries: Vec::new(),
        }
    }

    /// Returns a list of transactions.
    pub fn entries(&self) -> impl Iterator<Item = &MempoolEntry> {
        self.entries.iter()
    }

    /// Returns the size of the mempool in number of transactions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Updates timestamp and re-applies txs to filter out the outdated ones.
    pub fn update_timestamp(&mut self, timestamp_ms: u64) {
        self.timestamp_ms = timestamp_ms;
        self.update_mempool(None);
    }

    /// Updates the state of the blockchain and removes conflicting transactions.
    pub fn update_state(&mut self, state: BlockchainState, catchup: &Catchup) {
        self.timestamp_ms = state.tip.timestamp_ms;
        self.state = state;
        self.update_mempool(Some(catchup));
    }

    /// Adds transaction to the mempool and verifies it.
    /// Returns the reference to the stored mempool entry.
    pub fn append(
        &mut self,
        block_tx: BlockTx,
        bp_gens: &BulletproofGens,
    ) -> Result<&MempoolEntry, BlockchainError> {
        // 1. Check the header
        check_tx_header(
            &block_tx.tx.header,
            self.timestamp_ms,
            self.state.tip.version,
        )?;

        // 2. Verify the tx
        let verified_tx = block_tx
            .tx
            .verify(bp_gens)
            .map_err(|e| BlockchainError::TxValidation(e))?;

        // 3. Apply to the state
        self.apply_tx(&verified_tx.log, &block_tx.proofs, None)?;

        // 4. Save in the list
        self.entries.push(MempoolEntry {
            block_tx,
            verified_tx,
        });

        // 5. Return the reference to the entry we've just added.
        Ok(self.entries.last().unwrap())
    }

    /// Creates a new block header and a new blockchain state using the current set of transactions.
    /// Block header is accesible through the `tip` field on the new `BlockchainState` value.
    pub fn make_block(&self) -> (BlockchainState, Catchup) {
        let txroot = MerkleTree::root(
            b"ZkVM.txroot",
            self.entries.iter().map(|mtx| mtx.block_tx.witness_hash()),
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

        (new_state, new_catchup)
    }

    fn update_mempool(&mut self, catchup: Option<&Catchup>) {
        // reset the utreexo to the original state
        self.work_utreexo = self.state.utreexo.work_forest();

        // extract old
        let old_entries = mem::replace(&mut self.entries, Vec::new());

        for entry in old_entries.into_iter() {
            let result = check_tx_header(
                &entry.block_tx.tx.header,
                self.timestamp_ms,
                self.state.tip.version,
            )
            .and_then(|_| self.apply_tx(&entry.verified_tx.log, &entry.block_tx.proofs, catchup));
            if result.is_ok() {
                // put the entry back into the mempool if it's still valid
                self.entries.push(entry);
            }
        }
    }

    fn apply_tx(
        &mut self,
        txlog: &TxLog,
        utxo_proofs: &[utreexo::Proof],
        catchup: Option<&Catchup>,
    ) -> Result<(), BlockchainError> {
        // Update block makes sure the that if half of tx fails, all changes are undone.
        self.work_utreexo
            .batch(|wf| {
                let hasher = utreexo_hasher();
                let mut utxo_proofs = utxo_proofs.iter();

                for logentry in txlog.iter() {
                    match logentry {
                        // Remove item from the UTXO set
                        TxEntry::Input(contract_id) => {
                            let proof = utxo_proofs
                                .next()
                                .ok_or(BlockchainError::UtreexoProofMissing)?;

                            let updated_proof = match catchup {
                                Some(c) => {
                                    Some(c.update_proof(contract_id, proof.clone(), &hasher)?)
                                }
                                None => None,
                            };
                            let proof = updated_proof.as_ref().unwrap_or(proof);

                            wf.delete(contract_id, proof, &hasher)?;
                        }
                        // Add item to the UTXO set
                        TxEntry::Output(contract) => {
                            wf.insert(&contract.id(), &hasher);
                        }
                        // Ignore all other log entries
                        _ => {}
                    }
                }
                Ok(())
            })
            .map(|_| ())
    }
}
