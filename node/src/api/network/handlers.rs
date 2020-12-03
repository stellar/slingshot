use crate::api::data::{Cursor, HexId, MempoolStatus, State};
use crate::api::network::{requests, responses};
use std::convert::Infallible;
use crate::bc::BlockchainRef;
use crate::api::response::{ResponseResult, error};
use blockchain::{Mempool, BlockchainState, BlockchainProtocol};
use zkvm::encoding::ExactSizeEncodable;
use crate::api::data;

pub(super) async fn status(bc: BlockchainRef) -> ResponseResult<responses::Status> {
    let mempool = get::<&Mempool>();
    let status = mempool_status(mempool);

    let state = get::<&BlockchainState>();
    let tip = state.tip.clone().into();
    let utreexo = get();

    let state = State {
        tip,
        utreexo
    };

    Ok(responses::Status {
        mempool: status,
        state,
        peers: get()
    })
}

pub(super) async fn mempool(cursor: Cursor, bc: BlockchainRef) -> ResponseResult<responses::MempoolTxs> {
    let offset = cursor.cursor.parse::<usize>()
        .map_err(|_| error::invalid_cursor())?;
    let elements = Cursor::DEFAULT_ELEMENTS_PER_PAGE as usize;

    let mempool = get::<&Mempool>();
    let status = mempool_status(mempool);
    let txs = get::<std::slice::Iter<blockchain::BlockTx>>();
    let txs = txs.skip(offset).take(elements).map(|tx| Into::<data::Tx>::into(tx.clone())).collect::<Vec<_>>();

    Ok(responses::MempoolTxs {
        cursor: Cursor { cursor: (offset + elements).to_string() },
        status,
        txs
    })
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

fn mempool_status(mempool: &Mempool) -> MempoolStatus {
    let count = mempool.entries().count() as u64;
    let size = mempool.len() as u64;
    let feerate = get();

    MempoolStatus {
        count,
        size,
        feerate
    }
}

fn get<T>() -> T {
    unimplemented!()
}
