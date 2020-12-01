use serde::Serialize;

use crate::api::data::MempoolStatus;
use zkvm::{Tx, TxHeader};
use blockchain::{BlockHeader, BlockTx};

#[derive(Serialize)]
pub struct MempoolTxs {
    pub cursor: Vec<u8>,
    pub status: MempoolStatus,
    pub txs: Vec<Tx>
}

#[derive(Serialize)]
pub struct Blocks {
    pub cursor: Vec<u8>,
    pub blocks: Vec<BlockHeader>,
}

#[derive(Serialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<BlockTx>
}

#[derive(Serialize)]
pub struct TxResponse {
    pub status: TxStatus,
    pub tx: Tx,
}

#[derive(Serialize)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: u64,
    pub block_id: [u8; 32],
}
