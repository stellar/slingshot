use crate::api::data::{Cursor, HexId};
use crate::api::network::requests;
use std::convert::Infallible;

pub(super) async fn status() -> Result<impl warp::Reply, Infallible> {
    Ok("Status")
}

pub(super) async fn mempool(cursor: Cursor) -> Result<impl warp::Reply, Infallible> {
    Ok("Mempool")
}

pub(super) async fn blocks(cursor: Cursor) -> Result<impl warp::Reply, Infallible> {
    Ok("Blocks")
}

pub(super) async fn block(block_id: HexId) -> Result<impl warp::Reply, Infallible> {
    Ok("Block")
}

pub(super) async fn tx(tx_id: HexId) -> Result<impl warp::Reply, Infallible> {
    Ok("Tx")
}

pub(super) async fn submit(raw_tx: requests::RawTx) -> Result<impl warp::Reply, Infallible> {
    Ok("Submit")
}
