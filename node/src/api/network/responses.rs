use serde::Serialize;

use crate::api::data::MempoolStatus;
use crate::api::serde_utils::BigArray;
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

#[derive(Serialize)]
pub struct RawTx {
    header: TxHeader,
    program: Vec<u8>,
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    r1cs_proof: Vec<u8>,
    utreexo_proofs: Vec<Vec<u8>>,
}
