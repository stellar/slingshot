use crate::api::dto::{Cursor, HexId, MempoolStatusDTO, StateDTO, TxDTO};
use crate::api::network::{requests, responses};
use std::convert::Infallible;
use crate::bc::BlockchainRef;
use crate::api::response::{ResponseResult, error};
use blockchain::{Mempool, BlockchainState, BlockchainProtocol, BlockHeader, Block, BlockTx};
use zkvm::encoding::{ExactSizeEncodable, Encodable};
use crate::api::dto;
use zkvm::{Hash, Tx, TxHeader};
use crate::api::network::responses::TxStatus;
use zkvm::bulletproofs::r1cs::R1CSProof;
use musig::Signature;

pub(super) async fn status(bc: BlockchainRef) -> ResponseResult<responses::Status> {
    let bc_state = BlockchainState::make_initial(5, vec![]).0;
    let mempool = &Mempool::new(bc_state.clone(), 5);

    let status = mempool_status(mempool);
    let state = &bc_state;
    let tip = state.tip.clone().into();
    let utreexo = [None; 64];

    let state = StateDTO {
        tip,
        utreexo
    };

    let peers = vec![];

    Ok(responses::Status {
        mempool: status,
        state,
        peers
    })
}

pub(super) async fn mempool(cursor: Cursor, bc: BlockchainRef) -> ResponseResult<responses::MempoolTxs> {
    let bc_state = BlockchainState::make_initial(5, vec![]).0;
    let mempool = &Mempool::new(bc_state.clone(), 5);
    let txs_owned = Vec::<blockchain::BlockTx>::new();
    let txs = txs_owned.iter();

    let offset = cursor.cursor.parse::<usize>()
        .map_err(|_| error::invalid_cursor())?;
    let elements = cursor.count() as usize;

    let status = mempool_status(mempool);
    let txs = txs.skip(offset).take(elements).map(|tx| Into::<dto::TxDTO>::into(tx.clone())).collect::<Vec<_>>();

    Ok(responses::MempoolTxs {
        cursor: (offset + elements).to_string(),
        status,
        txs
    })
}

pub(super) async fn blocks(cursor: Cursor, bc: BlockchainRef) -> ResponseResult<responses::Blocks> {
    let blocks_headers = Vec::<BlockHeader>::new();

    let offset = cursor.cursor.parse::<usize>()
        .map_err(|_| error::invalid_cursor())?;
    let count = cursor.count() as usize;

    let headers = blocks_headers.iter().skip(offset).take(count).map(|b| b.clone().into()).collect::<Vec<_>>();
    Ok(responses::Blocks {
        cursor: (offset + count).to_string(),
        blocks: headers
    })
}

pub(super) async fn block(block_id: HexId, bc: BlockchainRef) -> ResponseResult<responses::Block> {
    let header = BlockHeader::make_initial(0, Hash::default());
    let txs = Vec::<blockchain::BlockTx>::new();
    
    Ok(responses::Block {
        header: header.into(),
        txs
    })
}

pub(super) async fn tx(tx_id: HexId, bc: BlockchainRef) -> ResponseResult<responses::TxResponse> {
    let tx = BlockTx {
        tx: Tx {
            header: TxHeader {
                version: 0,
                mintime_ms: 0,
                maxtime_ms: 0
            },
            program: vec![],
            signature: Signature { s: Default::default(), R: Default::default() },
            proof: R1CSProof::from_bytes(&[0; 1 + 15 * 32]).unwrap()
        },
        proofs: vec![]
    };

    let precomputed = tx.tx.precompute()
        .map_err(|_| error::tx_compute_error())?;

    let tx_dto = TxDTO {
        id: (precomputed.id.0).0,
        wid: tx.witness_hash().0,
        raw: hex::encode(tx.encode_to_vec()),
        fee: precomputed.feerate.fee(),
        size: precomputed.feerate.size() as u64,
    };

    let status = TxStatus {
        confirmed: true,
        block_height: 0,
        block_id: [0; 32]
    };

    Ok(responses::TxResponse {
        status,
        tx: tx_dto
    })
}

pub(super) async fn submit(raw_tx: requests::RawTx, bc: BlockchainRef) -> ResponseResult<responses::Submit> {
    unimplemented!()
}

fn mempool_status(mempool: &Mempool) -> MempoolStatusDTO {
    let count = mempool.entries().count() as u64;
    let size = mempool.len() as u64;
    let feerate = 0;

    MempoolStatusDTO {
        count,
        size,
        feerate
    }
}
