//! Blockchain data shared between all the users.
//! Represents the neutral view on the network w/o any private data.

use super::schema::*;
use super::util;
use zkvm::blockchain::{BlockHeader, BlockchainState};
use zkvm::utreexo;
use zkvm::{Tx, TxEntry};

use serde_json::Value as JsonValue;

#[derive(Debug, Queryable, Insertable)]
pub struct BlockRecord {
    pub height: i32, // FIXME: diesel doesn't allow u64 here...
    pub header_json: String,
    pub txs_json: String,
    pub utxo_proofs_json: String,
    pub state_json: String, // latest state will be used for *the* network state
}

impl BlockRecord {
    pub fn initial(network_state: &BlockchainState) -> Self {
        Self {
            height: 1,
            header_json: util::to_json(&network_state.tip),
            txs_json: "[]".to_string(),
            utxo_proofs_json: "[]".to_string(),
            state_json: util::to_json(&network_state),
        }
    }

    pub fn network_status_summary(&self) -> JsonValue {
        json!({
            "height": self.height,
            "block_id": hex::encode(self.block_header().id().0),
            "block_header": serde_json::from_str::<JsonValue>(&self.header_json).expect("Block header should be valid JSON."),
            "state": serde_json::from_str::<JsonValue>(&self.state_json).expect("State should be valid JSON."),
            "utxos_count": self.state().utreexo.count(),
        })
    }

    pub fn to_table_item(&self) -> JsonValue {
        let block_header = self.block_header();
        json!({
            "height": self.height,
            "id": hex::encode(block_header.id().0),
            "header": block_header,
            "txs": self.txs().len(),
        })
    }

    pub fn to_details(&self) -> JsonValue {
        let block_header = self.block_header();
        json!({
            "height": self.height,
            "id": hex::encode(block_header.id().0),
            "header": &util::to_json_value(&block_header),
            "txs": self.txs().into_iter().map(|tx| {
                Self::tx_details(&tx)
            }).collect::<Vec<_>>(),
        })
    }

    pub fn tx_details(tx: &Tx) -> JsonValue {
        let (txid, txlog) = tx
            .precompute()
            .expect("Our blockchain should not contain invalid transactions.");
        json!({
            "id": hex::encode(&txid),
            "header": &util::to_json_value(&tx.header),
            "inputs": &util::to_json_value(&txlog.iter().filter_map(|e| {
                match e {
                    TxEntry::Input(cid) => Some(cid),
                    _ => None
                }
            }).collect::<Vec<_>>()),
            "outputs": &util::to_json_value(&txlog.iter().filter_map(|e| {
                match e {
                    TxEntry::Output(c) => Some(c.id()),
                    _ => None
                }
            }).collect::<Vec<_>>()),
            "tx": &util::to_json_value(&tx),
            "program_hex": hex::encode(&tx.program),
            "program_asm": format!("{:?}", zkvm::Program::parse(&tx.program).expect("Our blockchain does not have invalid txs.")),
        })
    }

    pub fn block_header(&self) -> BlockHeader {
        util::from_valid_json(&self.header_json)
    }

    pub fn txs(&self) -> Vec<Tx> {
        util::from_valid_json(&self.txs_json)
    }

    pub fn utxo_proofs(&self) -> Vec<utreexo::Proof> {
        util::from_valid_json(&self.utxo_proofs_json)
    }

    pub fn state(&self) -> BlockchainState {
        util::from_valid_json(&self.state_json)
    }
}
