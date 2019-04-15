use bulletproofs::BulletproofGens;
use std::collections::{HashSet, VecDeque};

use super::block::{Block, BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::{Entry, TxLog, VMError, UTXO};

#[derive(Clone)]
pub struct BlockchainState {
    pub initial: BlockHeader,
    pub tip: BlockHeader,
    pub utxos: HashSet<UTXO>,
    pub nonces: VecDeque<([u8; 32], u64)>, // xxx need to keep sorted by expiration time; need fast lookup by anchor
    pub ref_ids: VecDeque<BlockID>,        // xxx need fast lookup by blockID

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
            nonces: VecDeque::new(),
            ref_ids: VecDeque::new(),
        }
    }

    pub fn apply_block<F>(
        &self,
        b: &Block,
        bp_gens: &BulletproofGens,
    ) -> Result<BlockchainState, BlockchainError> {
        let txlogs = b.validate(&self.tip, bp_gens)?;
        let mut new_state = self.clone();

        // Remove expired nonces.
        while let Some(nonce_pair) = new_state.nonces.front() {
            if nonce_pair.1 >= b.header.timestamp_ms {
                break;
            }
            new_state.nonces.pop_front();
        }

        for txlog in txlogs.iter() {
            if let Err(err) = new_state.apply_txlog(&txlog) {
                return Err(BlockchainError::TxValidation(err));
            }
        }

        Ok(new_state)
    }

    fn apply_txlog(&mut self, txlog: &TxLog) -> Result<(), VMError> {
        for entry in txlog.iter() {
            if let Entry::Nonce(blockID, exp_ms, anchor) = entry {
                // xxx note, when filling in this code, rename the destructing vars to remove the leading _
                // xxx check blockID is self.initialID or in self.ref_ids
                // xxx check anchor is not in self.nonces
                // xxx add (anchor, exp_ms) to self.nonces
            }
        }

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
