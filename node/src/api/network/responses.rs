use serde::Serialize;

use crate::api::data::MempoolStatus;
use zkvm::{Tx, TxHeader};
use blockchain::{BlockHeader, BlockTx};

#[derive(Serialize)]
pub struct MempoolTxs {
    cursor: Vec<u8>,
    status: MempoolStatus,
    txs: Vec<Tx>
}

#[derive(Serialize)]
pub struct Blocks {
    cursor: Vec<u8>,
    blocks: Vec<BlockHeader>,
}

#[derive(Serialize)]
pub struct Block {
    header: BlockHeader,
    txs: Vec<BlockTx>
}

#[derive(Serialize)]
pub struct TxResponse {
    status: TxStatus,
    tx: Tx,
}

#[derive(Serialize)]
pub struct TxStatus {
    confirmed: bool,
    block_height: u64,
    block_id: [u8; 32],
}
