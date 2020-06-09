use serde::{Deserialize, Serialize};

use super::block::{BlockHeader, BlockTx};
use super::errors::BlockchainError;
use crate::utreexo::{self, utreexo_hasher, Catchup, Forest};
use zkvm::bulletproofs::BulletproofGens;
use zkvm::{ContractID, MerkleTree, TxEntry, TxHeader, VerifiedTx};

/// State of the blockchain node.
#[derive(Clone, Serialize, Deserialize)]
pub struct BlockchainState {
    /// Latest block header in the chain.
    pub tip: BlockHeader,
    /// The utreexo state.
    pub utreexo: Forest,
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
        (BlockchainState { tip, utreexo }, proofs)
    }

    /// Applies the block to the current state and returns a new one.
    pub fn apply_block(
        &self,
        block_header: BlockHeader,
        block_txs: &[BlockTx],
        bp_gens: &BulletproofGens,
    ) -> Result<(BlockchainState, Catchup, Vec<VerifiedTx>), BlockchainError> {
        check_block_header(&block_header, &self.tip)?;

        let mut txroot_builder = MerkleTree::build_root(b"ZkVM.txroot");
        for block_tx in block_txs.iter() {
            // Check that tx header is consistent with the version / timestamp.
            check_tx_header(
                &block_tx.tx.header,
                block_header.timestamp_ms,
                block_header.version,
            )?;

            // Compute the commitment to all txs in a block.
            txroot_builder.append(&block_tx.witness_hash());
        }

        // Check the txroot commitment
        if block_header.txroot != txroot_builder.root() {
            return Err(BlockchainError::InconsistentHeader);
        }

        // At this point we know that we have all tx data authenticated w.r.t. to the origin of the block,
        // so we can perform more expensive verification steps.
        let mut work_forest = self.utreexo.work_forest();
        let utxo_hasher = utreexo_hasher::<ContractID>();
        let mut verified_txs = Vec::with_capacity(block_txs.len());
        for block_tx in block_txs.iter() {
            // TODO: this is a great place to do batch verification of signatures and bulletproofs.
            let verified_tx = block_tx.tx.verify(bp_gens)?;

            let mut utreexo_proofs = block_tx.proofs.iter();

            // Apply tx to the state
            for entry in verified_tx.log.iter() {
                match entry {
                    // Remove item from the UTXO set
                    TxEntry::Input(contract_id) => {
                        let proof = utreexo_proofs
                            .next()
                            .ok_or(BlockchainError::UtreexoProofMissing)?;

                        work_forest.delete(contract_id, proof, &utxo_hasher)?;
                    }
                    // Add item to the UTXO set
                    TxEntry::Output(contract) => {
                        work_forest.insert(&contract.id(), &utxo_hasher);
                    }
                    // Ignore all other log items
                    _ => {}
                }
            }

            verified_txs.push(verified_tx);
        }

        let (new_forest, new_catchup) = work_forest.normalize(&utxo_hasher);
        let utxoroot = new_forest.root(&utxo_hasher);

        // Check the utxo set commitment
        if block_header.utxoroot != utxoroot {
            return Err(BlockchainError::InconsistentHeader);
        }

        let new_state = BlockchainState {
            tip: block_header,
            utreexo: new_forest,
        };

        Ok((new_state, new_catchup, verified_txs))
    }
}

/// Checks the tx header for consistency with the block version and the timestamp.
pub fn check_tx_header(
    tx_header: &TxHeader,
    timestamp_ms: u64,
    block_version: u64,
) -> Result<(), BlockchainError> {
    check(
        timestamp_ms >= tx_header.locktime_ms,
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
