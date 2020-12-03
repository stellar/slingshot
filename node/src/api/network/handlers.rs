use crate::api::data::{Cursor, HexId};
use crate::api::network::requests;
use std::convert::Infallible;
use crate::bc::BlockchainRef;

pub(super) async fn status(bc: BlockchainRef) -> Result<impl warp::Reply, Infallible> {
    Ok("Status")
}

pub(super) async fn mempool(cursor: Cursor, bc: BlockchainRef) -> Result<impl warp::Reply, Infallible> {
    Ok("Mempool")
}

pub(super) async fn blocks(cursor: Cursor, bc: BlockchainRef) -> Result<impl warp::Reply, Infallible> {
    Ok("Blocks")
}

pub(super) async fn block(block_id: HexId, bc: BlockchainRef) -> Result<impl warp::Reply, Infallible> {
    Ok("Block")
}

pub(super) async fn tx(tx_id: HexId, bc: BlockchainRef) -> Result<impl warp::Reply, Infallible> {
    Ok("Tx")
}

pub(super) async fn submit(raw_tx: requests::RawTx, bc: BlockchainRef) -> Result<impl warp::Reply, Infallible> {
    Ok("Submit")
}
