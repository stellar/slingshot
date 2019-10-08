use core::borrow::Borrow;
use serde::{Deserialize, Serialize};

use super::block::{Block, BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::utreexo::{self, Catchup, Forest, NodeHasher, WorkForest};
use crate::{ContractID, MerkleTree, Tx, TxEntry, TxHeader, TxLog, VerifiedTx};

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

impl BlockchainState {
    /// Creates an initial block with a given starting set of utxos.
    pub fn make_initial<I>(timestamp_ms: u64, utxos: I) -> (BlockchainState, Vec<utreexo::Proof>)
    where
        I: IntoIterator<Item = ContractID> + Clone,
    {
        let hasher = NodeHasher::new();
        let (_, utreexo, catchup) = Forest::new()
            .update(&hasher, |forest| {
                for utxo in utxos.clone() {
                    forest.insert(&utxo, &hasher);
                }
                Ok(())
            })
            .unwrap(); // safe to unwrap because we only insert which never fails.

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

    /// Creates a new block with a set of verified transactions.
    /// Also returns a new blockchain state.
    pub fn make_block<P: Borrow<utreexo::Proof>>(
        &self,
        block_version: u64,
        timestamp_ms: u64,
        ext: Vec<u8>,
        txs: Vec<Tx>, // TBD: get an iterator of transactions and return a block header
        utxo_proofs: impl IntoIterator<Item = P>,
    ) -> Result<(Block, BlockchainState), BlockchainError> {
        // Check the block header w.r.t. previous header.
        // See also `check_block_header`.
        check(
            block_version >= self.tip.version,
            BlockchainError::InconsistentHeader,
        )?;
        check(
            timestamp_ms > self.tip.timestamp_ms,
            BlockchainError::InconsistentHeader,
        )?;

        let mut work_forest = self.utreexo.work_forest();
        let mut utxo_proofs = utxo_proofs.into_iter();
        let mut txroot_builder = MerkleTree::build_root(b"ZkVM.txroot");
        let hasher = NodeHasher::new();

        // We don't waste time verifying transactions here, they should've been verified by mempool.
        // Maybe if it makes sense to wrap Tx in VerifiedTx. But do so cleverly, because on the verifier's end
        // we want to avoid unnecessary copying or unergonomic moving of Tx into VerifiedTx, and
        // we don't care about the original Tx in the verifier's tx anyway.
        for tx in txs.iter() {
            check_tx_header(&tx.header, timestamp_ms, block_version)?;

            let (txid, txlog) = tx
                .precompute()
                .map_err(|vmerr| BlockchainError::TxValidation(vmerr))?;

            txroot_builder.append(&txid);

            apply_tx(&mut work_forest, &txlog, &mut utxo_proofs, &hasher)?;
        }

        let txroot = txroot_builder.root();
        let (new_forest, new_catchup) = work_forest.normalize(&hasher);
        let utxoroot = new_forest.root(&hasher);

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
        };

        let new_state = BlockchainState {
            initial_id: self.initial_id,
            tip: new_block.header.clone(),
            utreexo: new_forest,
            catchup: new_catchup,
        };

        Ok((new_block, new_state))
    }

    /// Applies the block to the current state and returns a new one.
    pub fn apply_block<T, P>(
        &mut self,
        block_header: BlockHeader,
        verified_txs: impl IntoIterator<Item = T>,
        utxo_proofs: impl IntoIterator<Item = P>,
    ) -> Result<BlockchainState, BlockchainError>
    where
        T: Borrow<VerifiedTx>,
        P: Borrow<utreexo::Proof>,
    {
        check_block_header(&block_header, &self.tip)?;

        // Check all the txs' headers, compute txid and apply all txs to the state.
        let mut work_forest = self.utreexo.work_forest();
        let mut utxo_proofs = utxo_proofs.into_iter();
        let mut txroot_builder = MerkleTree::build_root(b"ZkVM.txroot");
        let hasher = NodeHasher::new();
        for vtx in verified_txs.into_iter() {
            let vtx = vtx.borrow();
            check_tx_header(&vtx.header, block_header.timestamp_ms, block_header.version)?;
            txroot_builder.append(&vtx.id);
            apply_tx(&mut work_forest, &vtx.log, &mut utxo_proofs, &hasher)?;
        }
        let (new_forest, new_catchup) = work_forest.normalize(&hasher);
        let utxoroot = new_forest.root(&hasher);
        let txroot = txroot_builder.root();

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

/// Applies transaction to the Utreexo forest
pub(crate) fn apply_tx<P>(
    work_forest: &mut WorkForest,
    txlog: &TxLog,
    utxo_proofs: impl IntoIterator<Item = P>,
    hasher: &NodeHasher<ContractID>,
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
pub(crate) fn check_tx_header(
    tx_header: &TxHeader,
    timestamp_ms: u64,
    block_version: u64,
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
