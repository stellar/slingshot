use bulletproofs::BulletproofGens;
use std::collections::HashSet;

use super::block::{Block, BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::{ContractID, TxEntry, TxLog, VMError};

#[derive(Clone)]
pub struct BlockchainState {
    pub initial: BlockHeader,
    pub tip: BlockHeader,
    pub utxos: HashSet<ContractID>,

    pub initial_id: BlockID,
}

impl BlockchainState {
    pub fn make_initial(timestamp_ms: u64) -> BlockchainState {
        let initial_header = BlockHeader::make_initial(timestamp_ms);
        BlockchainState {
            initial: initial_header.clone(),
            initial_id: initial_header.id(),
            tip: initial_header,
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
                TxEntry::Input(input) => {
                    if !self.utxos.remove(&input) {
                        return Err(VMError::InvalidInput);
                    }
                }

                // Add output entry to UTXO set
                TxEntry::Output(output) => {
                    self.utxos.insert(output.id());
                }
                _ => {}
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use curve25519_dalek::scalar::Scalar;
    use rand::RngCore;

    use super::*;
    use crate::{Anchor, Contract, Data, PortableItem, Predicate, VerificationKey};

    fn rand_item() -> PortableItem {
        let mut bytes = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut bytes);
        PortableItem::Data(Data::Opaque(bytes.to_vec()))
    }

    fn rand_contract() -> Contract {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        let privkey = &Scalar::random(&mut rand::thread_rng());
        Contract::new(
            Predicate::Key(VerificationKey::from_secret(privkey)),
            vec![rand_item(), rand_item(), rand_item()],
            Anchor::from_raw_bytes(bytes),
        )
    }

    #[test]
    fn test_apply_txlog() {
        let mut state = BlockchainState::make_initial(0u64);

        // Add two outputs
        let (output0, output1) = (rand_contract(), rand_contract());
        state
            .apply_txlog(&vec![
                TxEntry::Output(output0.clone()),
                TxEntry::Output(output1.clone()),
            ])
            .unwrap();
        state
            .apply_txlog(&vec![TxEntry::Input(output0.id())])
            .unwrap();

        // Check that output0 was consumed
        assert!(!state.utxos.contains(&output0.id()));
        assert!(state.utxos.contains(&output1.id()));

        // Consume output1
        state
            .apply_txlog(&vec![TxEntry::Input(output1.id())])
            .unwrap();
        assert_eq!(state.utxos.is_empty(), true);

        // Check error on consuming already-consumed UTXO
        assert!(state
            .apply_txlog(&vec![TxEntry::Input(output1.id())])
            .is_err());
    }
}
