mod handlers;
mod requests;
mod responses;

use crate::api::types::{Cursor, HexId};
use crate::api::warp_utils::{handle1, handle2};
use crate::bc::BlockchainRef;
use std::convert::Infallible;
use warp::Filter;

pub fn routes(
    bc: BlockchainRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    let status = path!("v1" / "network" / "status")
        .and(get())
        .and(with_bc(bc.clone()))
        .and_then(handle1(handlers::status));

    let mempool = path!("v1" / "network" / "mempool")
        .and(get())
        .and(query::<Cursor>())
        .and(with_bc(bc.clone()))
        .and_then(handle2(handlers::mempool));

    let blocks = path!("v1" / "network" / "blocks")
        .and(get())
        .and(query::<Cursor>())
        .and(with_bc(bc.clone()))
        .and_then(handle2(handlers::blocks));

    let block = path!("v1" / "network" / "block" / HexId)
        .and(get())
        .and(with_bc(bc.clone()))
        .and_then(handle2(handlers::block));

    let tx = path!("v1" / "network" / "tx" / HexId)
        .and(get())
        .and(with_bc(bc.clone()))
        .and_then(handle2(handlers::tx));

    let submit = path!("v1" / "network" / "submit")
        .and(post())
        .and(body::json())
        .and(with_bc(bc.clone()))
        .and_then(handle2(handlers::submit));

    status.or(mempool).or(blocks).or(block).or(tx).or(submit)
}

fn with_bc(
    bc: BlockchainRef,
) -> impl Filter<Extract = (BlockchainRef,), Error = Infallible> + Clone {
    warp::any().map(move || bc.clone())
}
