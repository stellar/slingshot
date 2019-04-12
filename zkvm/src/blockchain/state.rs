use bulletproofs::BulletproofGens;
use std::collections::HashSet;

use super::block::{Block, BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::{Entry, TxLog, VMError, UTXO};

#[derive(Clone)]
pub struct BlockchainState {
    pub initial: BlockHeader,
    pub tip: BlockHeader,
    pub utxos: HashSet<UTXO>,

    pub initial_id: BlockID,
}

impl BlockchainState {
    pub fn make_initial(timestamp_ms: u64, refscount: u64) -> BlockchainState {
        let initialHeader = BlockHeader::make_initial(timestamp_ms, refscount);
        BlockchainState {
            initial: initialHeader.clone(),
            initial_id: initialHeader.id(),
            tip: initialHeader,
            utxos: HashSet::new(),
        }
    }

    pub fn apply_block<F>(
        &self,
        b: &Block,
        bp_gens: &BulletproofGens,
    ) -> Result<BlockchainState, BlockchainError> {
        let txlogs = b.validate(&self.tip, bp_gens)?;
        let mut new_state = self.clone();

        for txlog in txlogs.iter() {
            if let Err(err) = new_state.apply_txlog(&txlog) {
                return Err(BlockchainError::TxValidation(err));
            }
        }

        Ok(new_state)
    }

    fn apply_txlog(&mut self, txlog: &TxLog) -> Result<(), VMError> {
        for entry in txlog.iter() {
            match entry {
                Entry::Input(contractID) => {
                    // xxx check contractID is in self.utxos
                    // xxx remove contractID
                }

                Entry::Output(output) => {
                    // xxx add output.id to self.utxos
                }

                _ => {}
            }
        }

        Ok(())
    }
}
