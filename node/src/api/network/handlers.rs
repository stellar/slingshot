use crate::api::data::{Cursor, HexId};
use crate::api::network::{requests, responses};
use std::convert::Infallible;
use crate::bc::BlockchainRef;
use crate::api::response::ResponseResult;

pub(super) async fn status(bc: BlockchainRef) -> ResponseResult<responses::Status> {
   unimplemented!()
}

pub(super) async fn mempool(cursor: Cursor, bc: BlockchainRef) -> ResponseResult<responses::MempoolTxs> {
    unimplemented!()
}

pub(super) async fn blocks(cursor: Cursor, bc: BlockchainRef) -> ResponseResult<responses::Blocks> {
    unimplemented!()
}

pub(super) async fn block(block_id: HexId, bc: BlockchainRef) -> ResponseResult<responses::Block> {
    unimplemented!()
}

pub(super) async fn tx(tx_id: HexId, bc: BlockchainRef) -> ResponseResult<responses::TxResponse> {
    unimplemented!()
}

pub(super) async fn submit(raw_tx: requests::RawTx, bc: BlockchainRef) -> ResponseResult<responses::Submit> {
    unimplemented!()
}
