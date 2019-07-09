use bulletproofs::BulletproofGens;
use core::borrow::Borrow;

use super::block::{Block, BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::utreexo::{self, Catchup, Forest, WorkForest};
use crate::{ContractID, MerkleTree, Tx, TxEntry, TxHeader, TxID, VerifiedTx, Verifier};

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
    // TODO: add mempool and prune transactions with descendants from it as new blocks appear.
}

// /// Mempool is a temporary storage that lets collecting and verifying unconfirmed transactions
// /// before including them in a block.
// pub struct Mempool {
//     timestamp: u64,
//     state: BlockchainState,
//     txs: Vec<Tx>, // TBD: track dependencies to prune tx with all its children
//     work_forest: WorkForest<ContractID>,
// }

impl BlockchainState {
    /// Creates an initial block with a given starting set of utxos.
    pub fn make_initial(
        timestamp_ms: u64,
        utxos: &[ContractID],
    ) -> (BlockchainState, Vec<utreexo::Proof>) {
        let (proofs, utreexo, catchup) = Forest::<ContractID>::new()
            .update(|forest| {
                let proofs = utxos
                    .iter()
                    .map(|utxo| forest.insert(&utxo))
                    .collect::<Vec<_>>();
                Ok(proofs)
            })
            .unwrap(); // never fails because we only insert

        let proofs = utxos
            .iter()
            .zip(proofs.into_iter())
            .map(|(utxo, proof)| catchup.update_proof(utxo, proof).unwrap())
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
    ) -> Result<BlockchainState, BlockchainError> {
        check_block_header(&block.header, &self.tip)?;

        let mut work_forest = self.utreexo.work_forest();

        let txroot = apply_txs(
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

        Ok(BlockchainState {
            initial_id: self.initial_id,
            tip: block.header.clone(),
            utreexo: new_forest,
            catchup: new_catchup,
        })
    }

    /// Creates a new block with a set of verified transactions.
    /// Also returns a new blockchain state.
    pub fn make_block(
        &self,
        block_version: u64,
        timestamp_ms: u64,
        ext: Vec<u8>,
        txs: Vec<Tx>,
        utxo_proofs: impl IntoIterator<Item = utreexo::Proof>,
        bp_gens: &BulletproofGens,
    ) -> Result<(Block, BlockchainState), BlockchainError> {
        check(
            block_version >= self.tip.version,
            BlockchainError::InconsistentHeader,
        )?;
        check(
            timestamp_ms > self.tip.timestamp_ms,
            BlockchainError::InconsistentHeader,
        )?;

        let mut work_forest = self.utreexo.work_forest();

        let txroot = apply_txs(
            block_version,
            timestamp_ms,
            txs.iter(),
            utxo_proofs,
            &mut work_forest,
            bp_gens,
        )?;

        let (new_forest, new_catchup) = work_forest.normalize();

        let utxoroot = new_forest.root();

        let new_block = Block {
            header: BlockHeader {
                version: block_version,
                height: self.tip.height + 1,
                prev: self.tip.id(),
                timestamp_ms,
                txroot,
                utxoroot,
                ext,
            },
            txs,
        };

        let new_state = BlockchainState {
            initial_id: self.initial_id,
            tip: new_block.header.clone(),
            utreexo: new_forest,
            catchup: new_catchup,
        };

        Ok((new_block, new_state))
    }
}

/// Applies a single transaction to the state.
fn apply_tx(
    block_version: u64,
    timestamp_ms: u64,
    tx: &Tx,
    utxo_proofs: impl IntoIterator<Item = utreexo::Proof>,
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
                    .delete(&contract_id, &proof)
                    .map_err(|e| BlockchainError::UtreexoError(e))?;
            }
            // Add item to the UTXO set
            TxEntry::Output(contract) => {
                let _new_item_proof = work_forest.insert(&contract.id());
            }
            _ => {}
        }
    }

    Ok(verified_tx)
}

/// Applies a list of transactions to the state and returns the txroot.
fn apply_txs<T: Borrow<Tx>>(
    block_version: u64,
    timestamp_ms: u64,
    txs: impl IntoIterator<Item = T>,
    utxo_proofs: impl IntoIterator<Item = utreexo::Proof>,
    mut work_forest: &mut WorkForest<ContractID>,
    bp_gens: &BulletproofGens,
) -> Result<[u8; 32], BlockchainError> {
    // TBD: change to a more compact (log(n)) merkle root hasher.
    let mut utxo_proofs = utxo_proofs.into_iter();
    let txids = txs
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
            .map(|vtx| vtx.id)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(MerkleTree::root(b"ZkVM.txroot", &txids))
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
