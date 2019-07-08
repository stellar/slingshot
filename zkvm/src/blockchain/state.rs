use bulletproofs::BulletproofGens;

use super::block::{Block, BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::utreexo::{self,Forest, Catchup};
use crate::{ContractID, Tx, VerifiedTx, TxEntry, TxID, TxLog, VMError, Verifier};

#[derive(Clone)]
pub struct BlockchainState {
    pub initial_id: BlockID,
    pub tip: BlockHeader,
    pub utreexo: Forest<ContractID>,
    pub catchup: Catchup<ContractID>,
}

impl BlockchainState {
    /// Creates an initial block with a given starting set of utxos.
    pub fn make_initial(timestamp_ms: u64, utxos: &[ContractID]) -> (BlockchainState, Vec<utreexo::Proof>) {
        let (proofs, utreexo, catchup) = Forest::<ContractID>::new().update(|forest| {
            let proofs = utxos.iter().map(|utxo| {
                forest.insert(&utxo)
            }).collect::<Vec<_>>();
            Ok(proofs)
        });
        
        let (utxoroot, utreexo, catchup) = utreexo.normalize();
        
        let proofs = utxos.iter().zip(proofs.into_iter()).map(|(utxo, proof)| {
            catchup.update_proof(utxo, proof).unwrap()
        }).collect::<Vec<_>>();

        let tip = BlockHeader::make_initial(timestamp_ms, utxoroot);
        let state = BlockchainState {
            initial_id: tip.id(),
            tip,
            utreexo,
        };

        (state, proofs)
    }

    /// Applies the block to the current state and returns a new one.
    pub fn apply_block<F>(
        &mut self,
        block: &Block,
        bp_gens: &BulletproofGens,
    ) -> Result<BlockchainState, BlockchainError> {

        // 1. Process all txs
        // 2. Verify block header and tx headers
        // 3. Apply txlogs 
        // 4. Verify txroot
        // 5. Verify utxo root
        // 6. Return new state and the new catchup structure

        check_block_header(&block.header, &self.tip.header)?;

        let work_forest = self.forest.work_forest();

        // TBD: change to a more compact (log(n)) merkle root hasher.
        let mut txids: Vec<TxID> = Vec::with_capacity(self.txs.len());

        let mut utxo_proofs = block.utxo_proofs();    
        for tx in block.txs.iter() {
            check_tx_header(&tx.header, &block.header)?;
            
            let verified_tx = Verifier::verify_tx(tx, bp_gens).map_err(|e| BlockchainError::TxValidation(e) )?;

            // remember txid for txroot computation
            let txid = TxID::from_log(&verified_tx.log);
            txids.push(txid);
            
            for entry in verified_tx.log.iter() {
                match entry {
                    // Remove input from UTXO set
                    TxEntry::Input(contract_id) => {
                        let proof = utxo_proofs.next().ok_or(BlockchainError::UtreexoProofMissing)?;
                        work_forest.delete(&contract_id, &proof).map_err(|e| BlockchainError::UtreexoError(e))?;
                    },
                    // Add output entry to UTXO set
                    TxEntry::Output(contract) => {
                        let _new_item_proof = work_forest.insert(&contract.id(), &proof);
                    },
                    _ => {}
                }
            }
        }

        let txroot = MerkleTree::root(b"ZkVM.txroot", &txids);
        if &block.header.txroot != txroot {
            return Err(BlockchainError::TxrootMismatch);
        }

        let (new_forest, new_catchup) = work_forest.normalize();

        if &block.header.utxoroot != new_forest.root() {
            return Err(BlockchainError::UtxorootMismatch);
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
        utxo_proofs: impl IntoIterator<Item=utreexo::Proof>,
    ) -> Result<(Block, BlockchainState), BlockchainError> {

        check(
            block_version >= self.tip.version,
            BlockchainError::VersionReversion,
        )?;
        check(
            timestamp_ms > self.tip.timestamp_ms,
            BlockchainError::BadBlockTimestamp,
        )?;

        let work_forest = self.forest.work_forest();

        // TBD: change to a more compact (log(n)) merkle root hasher.
        let mut txids: Vec<TxID> = Vec::with_capacity(self.txs.len());

        let mut utxo_proofs = utxo_proofs.into_iter();
        for tx in txs.iter() {
            check_tx_header(&tx.header, &block.header)?;
            
            let verified_tx = Verifier::verify_tx(tx, bp_gens).map_err(|e| BlockchainError::TxValidation(e) )?;

            // remember txid for txroot computation
            let txid = TxID::from_log(&verified_tx.log);
            txids.push(txid);
            
            for entry in verified_tx.log.iter() {
                match entry {
                    // Remove input from UTXO set
                    TxEntry::Input(contract_id) => {
                        let proof = utxo_proofs.next().ok_or(BlockchainError::UtreexoProofMissing)?;
                        work_forest.delete(&contract_id, &proof).map_err(|e| BlockchainError::UtreexoError(e))?;
                    },
                    // Add output entry to UTXO set
                    TxEntry::Output(contract) => {
                        let _new_item_proof = work_forest.insert(&contract.id(), &proof);
                    },
                    _ => {}
                }
            }
        }

        let txroot = MerkleTree::root(b"ZkVM.txroot", &txids);

        let (new_forest, new_catchup) = work_forest.normalize();

        let utxoroot = new_forest.root();

        let new_block = Self {
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

/// Verifies consistency of the block header with respect to the previous block header.
fn check_block_header(block_header: &BlockHeader, prev_header: &BlockHeader) -> Result<(),BlockchainError> {
    check(
        block_header.version >= prev_header.version,
        BlockchainError::VersionReversion,
    )?;
    if block_header.version == 1 {
        check(
            block_header.ext.len() == 0,
            BlockchainError::IllegalExtension,
        )?;
    }
    check(block_header.height == prev_header.height + 1, BlockchainError::BadHeight)?;
    check(block_header.prev == prev_header.id(), BlockchainError::MismatchedPrev)?;
    check(
        block_header.timestamp_ms > prev_header.timestamp_ms,
        BlockchainError::BadBlockTimestamp,
    )?;
    Ok(())
}

/// Checks the tx header for consistency with the block header.
fn check_tx_header(tx_header: &TxHeader, block_header: &BlockHeader) -> Result<(),BlockchainError> {
    check(tx_header.mintime_ms <= block_header.timestamp_ms, BlockchainError::BadTxTimestamp)?;
    check(tx_header.maxtime_ms >= block_header.timestamp_ms, BlockchainError::BadTxTimestamp)?;
    if block_header.version == 1 {
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
