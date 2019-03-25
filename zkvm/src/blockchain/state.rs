use crate::{Entry, UTXO, VMError};
use super::block::{Block, BlockHeader};
use std::collections::{HashSet, VecDeque};

#[derive(Clone)]
pub struct BCState {
    pub initial: BlockHeader,
    pub tip: BlockHeader,
    pub utxos: HashSet<UTXO>,
    pub nonces: VecDeque<([u8; 32], i64)>,
    pub ref_ids: VecDeque<BlockID>,

    pub initial_id: BlockID;
}

#[derive(Clone)]
impl BCState {
    pub fn make_initial(timestamp_ms: u64, refscount: u64) -> BCState {
        let initialHeader = BlockHeader::make_initial(timestamp_ms, refscount);
        State {
            initial: initialHeader.clone(),
            tip: initialHeader.clone(),
            utxos: HashSet::new(),
            nonces: VecDeque::new(),
            ref_ids: VecDeque::new(),
            initial_id: initialHeader.id()
        }
    }

    pub fn apply_block(&self, b: &Block) -> Result<BCState, VMError> {
        let txlogs = b.validate(&self.tip)?;
        let new_state = self.clone();

        // Remove expired nonces.
        while let Some(nonce_pair) = new_state.nonces.front() {
            if nonce_pair.1 >= timestamp_ms {
                break;
            }
            new_state.nonces.pop_front();
        }

        for txlog in txlogs.iter() {
            if let Err(err) = new_state.apply_txlog(&txlog) {
                return Err(err);
            }
        }
    }

    fn apply_txlog(&mut self) -> Result<(), VMError> {
        for entry in txlog.iter() {
            if let Entry::Nonce(blockID, exp_ms, anchor) = entry {
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
            }
        }

        Ok(())
    }
}
