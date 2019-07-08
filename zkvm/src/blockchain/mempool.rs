//! Mempool is a temporary storage that lets collecting and verifying unconfirmed transactions
//! before including them in a block.

use bulletproofs::BulletproofGens;

use super::block::{Block, BlockHeader, BlockID};
use super::state::{BlockchainState};
use super::errors::BlockchainError;
use crate::utreexo::{self,Forest, WorkForest, Catchup};
use crate::{ContractID, Tx, TxEntry, TxID, TxLog, VMError, Verifier};

/// Mempool is a temporary storage that lets collecting and verifying unconfirmed transactions
/// before including them in a block.
pub struct Mempool {
	state: BlockchainState,
	txs: Vec<Tx>, // TBD: track dependencies to prune tx with all its children
	work_forest: WorkForest<ContractID>,
}


impl Mempool {
	// TBD: store the list of txs, and a utreexo forest.
	// If a tx needs to be pruned, recompute the forest a-novo.


}

