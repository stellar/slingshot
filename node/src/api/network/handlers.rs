use crate::{
    api::{
        network::{requests, responses},
        response::{error, ResponseResult},
        types,
        types::{Cursor, HexId},
    },
    bc::BlockchainRef,
};
use blockchain::{BlockHeader, BlockchainState, Mempool};
use std::convert::TryFrom;
use zkvm::Tx;

pub(super) async fn status(bc: BlockchainRef) -> ResponseResult<responses::Status> {
    let bc_state = BlockchainState::make_initial(5, vec![]).0;
    let mempool = &Mempool::new(bc_state.clone(), 5);

    let status = mempool_status(mempool);
    let state = &bc_state;
    let tip = state.tip.clone().into();
    let utreexo = [None; 64];

    let state = types::State { tip, utreexo };

    let peers = vec![];

    Ok(responses::Status {
        mempool: status,
        state,
        peers,
    })
}

pub(super) async fn mempool(
    cursor: types::Cursor,
    bc: BlockchainRef,
) -> ResponseResult<responses::MempoolTxs> {
    let bc_state = BlockchainState::make_initial(5, vec![]).0;
    let mempool = &Mempool::new(bc_state.clone(), 5);
    let txs_owned = Vec::<blockchain::BlockTx>::new();
    let txs = txs_owned.iter();

    let offset = cursor
        .cursor
        .parse::<usize>()
        .map_err(|_| error::invalid_cursor())?;
    let elements = cursor.count() as usize;

    let status = mempool_status(mempool);
    let txs = txs
        .skip(offset)
        .take(elements)
        .map(|tx| types::Tx::try_from(tx.clone()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| error::tx_compute_error())?;

    Ok(responses::MempoolTxs {
        cursor: (offset + elements).to_string(),
        status,
        txs,
    })
}

pub(super) async fn blocks(cursor: Cursor, bc: BlockchainRef) -> ResponseResult<responses::Blocks> {
    let blocks_headers = Vec::<BlockHeader>::new();

    let offset = cursor
        .cursor
        .parse::<usize>()
        .map_err(|_| error::invalid_cursor())?;
    let count = cursor.count() as usize;

    let headers = blocks_headers
        .iter()
        .skip(offset)
        .take(count)
        .map(|b| b.clone().into())
        .collect::<Vec<_>>();
    Ok(responses::Blocks {
        cursor: (offset + count).to_string(),
        blocks: headers,
    })
}

pub(super) async fn block(block_id: HexId, bc: BlockchainRef) -> ResponseResult<responses::Block> {
    let header = BlockHeader::make_initial(0, zkvm::Hash::default());
    let txs = Vec::<blockchain::BlockTx>::new();

    Ok(responses::Block {
        header: header.into(),
        txs,
    })
}

pub(super) async fn tx(tx_id: HexId, bc: BlockchainRef) -> ResponseResult<responses::TxResponse> {
    let block_tx = blockchain::BlockTx {
        tx: Tx {
            header: zkvm::TxHeader {
                version: 0,
                mintime_ms: 0,
                maxtime_ms: 0,
            },
            program: vec![],
            signature: musig::Signature {
                s: Default::default(),
                R: Default::default(),
            },
            proof: zkvm::bulletproofs::r1cs::R1CSProof::from_bytes(&[0; 1 + 15 * 32]).unwrap(),
        },
        proofs: vec![],
    };

    let tx = types::Tx::try_from(block_tx).map_err(|_| error::tx_compute_error())?;

    let status = responses::TxStatus {
        confirmed: true,
        block_height: 0,
        block_id: [0; 32],
    };

    Ok(responses::TxResponse { status, tx })
}

pub(super) async fn submit(
    raw_tx: requests::RawTx,
    bc: BlockchainRef,
) -> ResponseResult<responses::Submit> {
    unimplemented!()
}

fn mempool_status(mempool: &Mempool) -> types::MempoolStatus {
    let count = mempool.entries().count() as u64;
    let size = mempool.len() as u64;
    let feerate = 0;

    types::MempoolStatus {
        count,
        size,
        feerate,
    }
}
