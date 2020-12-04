use serde::Serialize;

use crate::api::dto::{MempoolStatusDTO, StateDTO, PeerDTO, Cursor, TxDTO, BlockHeaderDTO};
use blockchain::{BlockTx};
use zkvm::{TxHeader};

#[derive(Serialize)]
pub struct Status {
    pub mempool: MempoolStatusDTO,
    pub state: StateDTO,
    pub peers: Vec<PeerDTO>
}

#[derive(Serialize)]
pub struct MempoolTxs {
    pub cursor: String,
    pub status: MempoolStatusDTO,
    pub txs: Vec<TxDTO>,
}

#[derive(Serialize)]
pub struct Blocks {
    pub cursor: String,
    pub blocks: Vec<BlockHeaderDTO>,
}

#[derive(Serialize)]
pub struct Block {
    pub header: BlockHeaderDTO,
    pub txs: Vec<BlockTx>,
}

#[derive(Serialize)]
pub struct TxResponse {
    pub status: TxStatus,
    pub tx: TxDTO,
}

#[derive(Serialize)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: u64,
    pub block_id: [u8; 32],
}

#[derive(Serialize)]
pub struct Submit {}
