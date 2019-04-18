use bulletproofs::BulletproofGens;
use std::collections::HashSet;

use super::block::{Block, BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::{ContractID, Entry, TxLog, VMError};

#[derive(Clone)]
pub struct BlockchainState {
    pub initial: BlockHeader,
    pub tip: BlockHeader,
    pub utxos: HashSet<ContractID>,

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
                // Remove input from UTXO set
                Entry::Input(input) => {
                    if !self.utxos.remove(&input) {
                        return Err(VMError::InvalidInput);
                    }
                }

                // Add output entry to UTXO set
                Entry::Output(output) => {
                    self.utxos.insert(output.id());
                }
                _ => {}
            }
        }

        Ok(())
    }

    fn apply_txlist(&mut self, txlist: &[TxLog]) -> Result<(), VMError> {
        for txlog in txlist.iter() {
            self.apply_txlog(txlog)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::RngCore;

    use super::*;
    use crate::{Anchor, Contract, Data, Output, PortableItem, Predicate, VerificationKey};

    fn rand_item() -> PortableItem {
        let mut bytes = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut bytes);
        PortableItem::Data(Data::Opaque(bytes.to_vec()))
    }

    fn rand_contract() -> Contract {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Contract {
            anchor: Anchor::from_raw_bytes(bytes),
            payload: vec![rand_item(), rand_item(), rand_item()],
            predicate: Predicate::Key(VerificationKey::from_secret(&Scalar::random(
                &mut rand::thread_rng(),
            ))),
        }
    }

    #[test]
    fn test_apply_txlog() {
        let mut state = BlockchainState::make_initial(0u64, 0u64);

        // Add two outputs
        let (output0, output1) = (Output::new(rand_contract()), Output::new(rand_contract()));
        state
            .apply_txlog(&vec![
                Entry::Output(output0.clone()),
                Entry::Output(output1.clone()),
            ])
            .unwrap();
        state
            .apply_txlog(&vec![Entry::Input(output0.id())])
            .unwrap();

        // Check that output0 was consumed
        assert!(!state.utxos.contains(&output0.id()));
        assert!(state.utxos.contains(&output1.id()));

        // Consume output1
        state
            .apply_txlog(&vec![Entry::Input(output1.id())])
            .unwrap();
        assert_eq!(state.utxos.is_empty(), true);

        // Check error on consuming already-consumed UTXO
        assert!(state
            .apply_txlog(&vec![Entry::Input(output1.id())])
            .is_err());
    }
}
