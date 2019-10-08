use bulletproofs::BulletproofGens;
use core::borrow::Borrow;
use serde::{Deserialize, Serialize};

use super::block::{Block, BlockHeader, BlockID, VerifiedBlock};
use super::errors::BlockchainError;
use crate::utreexo::{self, Catchup, Forest, NodeHasher, WorkForest};
use crate::{ContractID, Hash, MerkleTree, Tx, TxEntry, TxHeader, VerifiedTx};

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

/// All the data necessary for validating and applying transactions.
/// `BlockchainState` API uses it to apply a block of transactions.
/// `Mempool` API uses it to apply one transaction after another.
pub(super) struct ValidationContext {
    block_version: u64,
    timestamp_ms: u64,
    work_forest: WorkForest,
    hasher: NodeHasher<ContractID>,
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
        txs: Vec<Tx>,
        utxo_proofs: impl IntoIterator<Item = P>,
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

        let verified_txs = Tx::verify_batch(txs.iter(), bp_gens)
            .map_err(|vmerr| BlockchainError::TxValidation(vmerr))?;

        // TODO: use a more efficient way to compute merkle root w/o allocating another vec of hashes.
        let txroot = MerkleTree::root(
            b"ZkVM.txroot",
            &verified_txs.iter().map(|tx| tx.id).collect::<Vec<_>>(),
        );

        let mut ctx =
            ValidationContext::new(block_version, timestamp_ms, self.utreexo.work_forest());

        ctx.apply_txs_nonatomic(verified_txs.iter(), utxo_proofs)?;

        let (utxoroot, new_forest, new_catchup) = ctx.normalize_state();

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

    /// Applies the block to the current state and returns a new one.
    pub fn apply_block<P: Borrow<utreexo::Proof>>(
        &mut self,
        block: &VerifiedBlock,
        utxo_proofs: impl IntoIterator<Item = P>,
    ) -> Result<BlockchainState, BlockchainError> {
        let mut ctx = ValidationContext::new(
            block.header.version,
            block.header.timestamp_ms,
            self.utreexo.work_forest(),
        );

        // TODO: use a more efficient way to compute merkle root w/o allocating another vec of hashes.
        let txroot = MerkleTree::root(
            b"ZkVM.txroot",
            &block.txs.iter().map(|tx| tx.id).collect::<Vec<_>>(),
        );

        ctx.apply_txs_nonatomic(block.txs.iter(), utxo_proofs)?;

        if block.header.txroot != txroot {
            return Err(BlockchainError::InconsistentHeader);
        }

        let (utxoroot, new_forest, new_catchup) = ctx.normalize_state();

        if block.header.utxoroot != utxoroot {
            return Err(BlockchainError::InconsistentHeader);
        }

        let new_state = BlockchainState {
            initial_id: self.initial_id,
            tip: block.header.clone(),
            utreexo: new_forest,
            catchup: new_catchup,
        };

        Ok(new_state)
    }
}

impl ValidationContext {
    /// Create a new context with given block version, timestamp and work forest for utxos.
    pub fn new(block_version: u64, timestamp_ms: u64, work_forest: WorkForest) -> Self {
        Self {
            block_version,
            timestamp_ms,
            work_forest,
            hasher: NodeHasher::new(),
        }
    }

    /// Applies a list of transactions to the state and returns the txroot.
    /// FIXME: make this more sanely organized.
    fn apply_txs_nonatomic<T, P>(
        &mut self,
        txs: impl IntoIterator<Item = T>,
        utxo_proofs: impl IntoIterator<Item = P>,
    ) -> Result<(), BlockchainError>
    where
        T: Borrow<VerifiedTx>,
        P: Borrow<utreexo::Proof>,
    {
        let mut utxo_proofs = utxo_proofs.into_iter();

        for tx in txs {
            self.check_tx_header(&tx.borrow().header)?;
            Self::apply_tx_nonatomic(&mut self.work_forest, &self.hasher, tx, &mut utxo_proofs)?;
        }

        Ok(())
    }

    /// Applies a single transaction to the state.
    /// If one of the inputs has an invalid proof or already spent,
    /// state is left unchanged.
    pub fn apply_tx<T, P>(
        &mut self,
        tx: T,
        utxo_proofs: impl IntoIterator<Item = P>,
    ) -> Result<(), BlockchainError>
    where
        T: Borrow<VerifiedTx>,
        P: Borrow<utreexo::Proof>,
    {
        self.check_tx_header(&tx.borrow().header)?;
        let hasher = &self.hasher;
        self.work_forest.transaction(|work_forest| {
            Self::apply_tx_nonatomic(work_forest, hasher, tx, utxo_proofs)
        })
    }
    /// Applies a single transaction to the state.
    /// WARNING: this leaves the Utreexo state modified if one of the updates failed.
    fn apply_tx_nonatomic<T, P>(
        work_forest: &mut WorkForest,
        hasher: &NodeHasher<ContractID>,
        verified_tx: T,
        utxo_proofs: impl IntoIterator<Item = P>,
    ) -> Result<(), BlockchainError>
    where
        T: Borrow<VerifiedTx>,
        P: Borrow<utreexo::Proof>,
    {
        let mut utxo_proofs = utxo_proofs.into_iter();
        let verified_tx = verified_tx.borrow();

        for entry in verified_tx.log.iter() {
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

    /// Normalizes the state into a new compact forest.
    pub fn normalize_state(self) -> (Hash, Forest, Catchup) {
        let (forest, catchup) = self.work_forest.normalize(&self.hasher);
        let root = forest.root(&self.hasher);
        (root, forest, catchup)
    }

    /// Checks the tx header for consistency with the block header.
    fn check_tx_header(&self, tx_header: &TxHeader) -> Result<(), BlockchainError> {
        check(
            tx_header.mintime_ms <= self.timestamp_ms,
            BlockchainError::BadTxTimestamp,
        )?;
        check(
            tx_header.maxtime_ms >= self.timestamp_ms,
            BlockchainError::BadTxTimestamp,
        )?;
        if self.block_version == 1 {
            check(tx_header.version == 1, BlockchainError::BadTxVersion)?;
        }
        Ok(())
    }
}

#[inline]
fn check<E>(cond: bool, err: E) -> Result<(), E> {
    if !cond {
        return Err(err);
    }
    Ok(())
}
