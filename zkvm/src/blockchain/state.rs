use bulletproofs::BulletproofGens;

use super::block::{Block, BlockHeader, BlockID};
use super::errors::BlockchainError;
use crate::utreexo::{self,Utreexo};
use crate::{ContractID, Tx, TxEntry, TxID, TxLog, VMError, Verifier};

#[derive(Clone)]
pub struct BlockchainState {
    pub initial_id: BlockID,
    pub tip: BlockHeader,
    pub utreexo: Utreexo<ContractID>,
}

impl BlockchainState {
    /// Creates an initial block with a given starting set of utxos.
    pub fn make_initial(timestamp_ms: u64, utxos: &[ContractID]) -> (BlockchainState, Vec<utreexo::Proof>) {
        let (proofs, utreexo, catchup) = Utreexo::<ContractID>::new().update(|forest| {
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

    /// Applies the block to the state
    pub fn apply_block<F>(
        &self,
        block: &Block,
        bp_gens: &BulletproofGens,
    ) -> Result<BlockchainState, BlockchainError> {
        let txlogs = block.validate(&self.tip, bp_gens)?;
        let mut new_state = self.clone();

        for txlog in txlogs.iter() {
            new_state.apply_txlog(&txlog).map_err(|e| {
                BlockchainError::TxValidation(e)
            })?;
        }

        Ok(new_state)
    }

    pub fn apply_txlog(&mut self, txlog: &TxLog) -> Result<(), VMError> {
        unimplemented!();
        for entry in txlog.iter() {
            match entry {
                // Remove input from UTXO set
                TxEntry::Input(input) => {
                    // match self.utxos.iter().position(|x| x == input) {
                    //     Some(pos) => self.utxos.remove(pos),
                    //     None => return Err(VMError::InvalidInput),
                    // };
                }

                // Add output entry to UTXO set
                TxEntry::Output(output) => {
                    // self.utxos.push(output.id());
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Executes a transaction, returning its tx ID and tx log.
    pub fn execute_tx(
        tx: &Tx,
        bp_gens: &BulletproofGens,
        block_version: u64,
        timestamp_ms: u64,
    ) -> Result<(TxID, TxLog), BlockchainError> {
        if tx.header.mintime_ms > timestamp_ms || tx.header.maxtime_ms < timestamp_ms {
            return Err(BlockchainError::BadTxTimestamp);
        }

        // Check that, for the current block version, this tx version is
        // supported. For block versions higher than 1, we do not yet know
        // what tx versions to support, so we accept all.
        if block_version == 1 && tx.header.version != 1 {
            return Err(BlockchainError::VersionReversion);
        }

        // Verify tx
        let vtx = Verifier::verify_tx(tx, bp_gens).map_err(|e| BlockchainError::TxValidation(e))?;
        Ok((vtx.id, vtx.log))
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
        unimplemented!();
        let mut state = BlockchainState::make_initial(0u64, &[]);

        /*
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
            */
    }
}
