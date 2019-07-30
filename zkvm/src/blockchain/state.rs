use bulletproofs::BulletproofGens;
use core::borrow::Borrow;

use super::block::{Block, BlockHeader, BlockID, VerifiedBlock};
use super::errors::BlockchainError;
use crate::utreexo::{self, Catchup, Forest, WorkForest};
use crate::{ContractID, MerkleTree, Tx, TxEntry, TxHeader, VerifiedTx, Verifier};

/// State of the blockchain node.
#[derive(Clone)]
pub struct BlockchainState {
    /// Initial block of the given network.
    pub initial_id: BlockID,
    /// Latest block header in the chain.
    pub tip: BlockHeader,
    /// The utreexo state.
    pub utreexo: Forest<ContractID>,
    /// The catchup structure to auto-update the proofs made against the previous state.
    pub catchup: Catchup<ContractID>,
}

impl BlockchainState {
    /// Creates an initial block with a given starting set of utxos.
    pub fn make_initial(
        timestamp_ms: u64,
        utxos: impl IntoIterator<Item = ContractID>,
    ) -> (BlockchainState, Vec<utreexo::Proof>) {
        // Q: why do we need to re-use an ?
        let (utxos_and_proofs, utreexo, catchup) = Forest::<ContractID>::new()
            .update(|forest| {
                let utxos_and_proofs = utxos
                    .into_iter()
                    .map(|utxo| {
                        forest.insert(&utxo);
                        utxo
                    })
                    .collect::<Vec<_>>();
                Ok(utxos_and_proofs)
            })
            .unwrap(); // safe to unwrap because we only insert which never fails.

        let proofs = utxos_and_proofs
            .into_iter()
            .map(|utxo| catchup.update_proof(&utxo, None).unwrap())
            .collect::<Vec<_>>();

        let tip = BlockHeader::make_initial(timestamp_ms, utreexo.root());
        let state = BlockchainState {
            initial_id: tip.id(),
            tip,
            utreexo,
            catchup,
        };

        (state, proofs)
    }

    /// Applies the block to the current state and returns a new one.
    pub fn apply_block(
        &mut self,
        block: &Block,
        bp_gens: &BulletproofGens,
    ) -> Result<(VerifiedBlock, BlockchainState), BlockchainError> {
        check_block_header(&block.header, &self.tip)?;

        let mut work_forest = self.utreexo.work_forest();

        let (txroot, verified_txs) = apply_txs(
            block.header.version,
            block.header.timestamp_ms,
            block.txs.iter(),
            block.utxo_proofs(),
            &mut work_forest,
            bp_gens,
        )?;

        if block.header.txroot != txroot {
            return Err(BlockchainError::InconsistentHeader);
        }

        let (new_forest, new_catchup) = work_forest.normalize();

        if block.header.utxoroot != new_forest.root() {
            return Err(BlockchainError::InconsistentHeader);
        }

        let verified_block = VerifiedBlock {
            header: block.header.clone(),
            txs: verified_txs,
        };

        let new_state = BlockchainState {
            initial_id: self.initial_id,
            tip: block.header.clone(),
            utreexo: new_forest,
            catchup: new_catchup,
        };

        Ok((verified_block, new_state))
    }

    /// Creates a new block with a set of verified transactions.
    /// Also returns a new blockchain state.
    pub fn make_block(
        &self,
        block_version: u64,
        timestamp_ms: u64,
        ext: Vec<u8>,
        txs: Vec<Tx>,
        utxo_proofs: Vec<utreexo::Proof>,
        bp_gens: &BulletproofGens,
    ) -> Result<(Block, VerifiedBlock, BlockchainState), BlockchainError> {
        check(
            block_version >= self.tip.version,
            BlockchainError::InconsistentHeader,
        )?;
        check(
            timestamp_ms > self.tip.timestamp_ms,
            BlockchainError::InconsistentHeader,
        )?;

        let mut work_forest = self.utreexo.work_forest();

        let (txroot, verified_txs) = apply_txs(
            block_version,
            timestamp_ms,
            txs.iter(),
            utxo_proofs.iter(),
            &mut work_forest,
            bp_gens,
        )?;

        let (new_forest, new_catchup) = work_forest.normalize();

        let utxoroot = new_forest.root();

        let header = BlockHeader {
            version: block_version,
            height: self.tip.height + 1,
            prev: self.tip.id(),
            timestamp_ms,
            txroot,
            utxoroot,
            ext,
        };

        let new_block = Block {
            header: header.clone(),
            txs,
            all_utxo_proofs: utxo_proofs,
        };

        let new_block_verified = VerifiedBlock {
            header,
            txs: verified_txs,
        };

        let new_state = BlockchainState {
            initial_id: self.initial_id,
            tip: new_block.header.clone(),
            utreexo: new_forest,
            catchup: new_catchup,
        };

        Ok((new_block, new_block_verified, new_state))
    }
}

/// Applies a single transaction to the state.
fn apply_tx<P: Borrow<utreexo::Proof>>(
    block_version: u64,
    timestamp_ms: u64,
    tx: &Tx,
    utxo_proofs: impl IntoIterator<Item = P>,
    work_forest: &mut WorkForest<ContractID>,
    bp_gens: &BulletproofGens,
) -> Result<VerifiedTx, BlockchainError> {
    let mut utxo_proofs = utxo_proofs.into_iter();

    check_tx_header(&tx.header, block_version, timestamp_ms)?;

    let verified_tx =
        Verifier::verify_tx(tx, bp_gens).map_err(|e| BlockchainError::TxValidation(e))?;

    for entry in verified_tx.log.iter() {
        match entry {
            // Remove item from the UTXO set
            TxEntry::Input(contract_id) => {
                let proof = utxo_proofs
                    .next()
                    .ok_or(BlockchainError::UtreexoProofMissing)?;
                work_forest
                    .delete(&contract_id, proof.borrow())
                    .map_err(|e| BlockchainError::UtreexoError(e))?;
            }
            // Add item to the UTXO set
            TxEntry::Output(contract) => {
                // TBD: this proof is useless, but we need it for deleting transient
                // utxos inserted in the same block - how this will be resolved?
                let _new_item_proof = work_forest.insert(&contract.id());
            }
            _ => {}
        }
    }

    Ok(verified_tx)
}

/// Applies a list of transactions to the state and returns the txroot.
fn apply_txs<T: Borrow<Tx>, P: Borrow<utreexo::Proof>>(
    block_version: u64,
    timestamp_ms: u64,
    txs: impl IntoIterator<Item = T>,
    utxo_proofs: impl IntoIterator<Item = P>,
    mut work_forest: &mut WorkForest<ContractID>,
    bp_gens: &BulletproofGens,
) -> Result<([u8; 32], Vec<VerifiedTx>), BlockchainError> {
    let mut utxo_proofs = utxo_proofs.into_iter();
    let verified_txs = txs
        .into_iter()
        .map(|tx| {
            apply_tx(
                block_version,
                timestamp_ms,
                tx.borrow(),
                &mut utxo_proofs,
                &mut work_forest,
                bp_gens,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;

    // TBD: change this O(n) allocation to a more compact (log(n)) merkle root hasher.
    let txids = verified_txs.iter().map(|tx| tx.id).collect::<Vec<_>>();
    let txroot = MerkleTree::root(b"ZkVM.txroot", &txids);
    Ok((txroot, verified_txs))
}

/// Verifies consistency of the block header with respect to the previous block header.
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
        block_header.prev == prev_header.id(),
        BlockchainError::InconsistentHeader,
    )?;
    check(
        block_header.timestamp_ms > prev_header.timestamp_ms,
        BlockchainError::InconsistentHeader,
    )?;
    Ok(())
}

/// Checks the tx header for consistency with the block header.
fn check_tx_header(
    tx_header: &TxHeader,
    block_version: u64,
    timestamp_ms: u64,
) -> Result<(), BlockchainError> {
    check(
        tx_header.mintime_ms <= timestamp_ms,
        BlockchainError::BadTxTimestamp,
    )?;
    check(
        tx_header.maxtime_ms >= timestamp_ms,
        BlockchainError::BadTxTimestamp,
    )?;
    if block_version == 1 {
        check(tx_header.version == 1, BlockchainError::BadTxVersion)?;
    }
    Ok(())
}

fn check(cond: bool, err: BlockchainError) -> Result<(), BlockchainError> {
    if !cond {
        return Err(err);
    }
    Ok(())
}
