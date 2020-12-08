mod handlers;
mod requests;
mod responses;

use crate::api::types::{Cursor, HexId};
use warp::Filter;
use crate::bc::BlockchainRef;
use std::convert::Infallible;
use crate::api::warp_utils::{handle2, handle1};

pub fn routes(bc: BlockchainRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    status(bc.clone())
        .or(mempool(bc.clone()))
        .or(blocks(bc.clone()))
        .or(block(bc.clone()))
        .or(tx(bc.clone()))
        .or(submit(bc))
}

fn status(bc: BlockchainRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "status")
        .and(get())
        .and(with_bc(bc))
        .and_then(handle1(handlers::status))
}

fn mempool(bc: BlockchainRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "mempool")
        .and(get())
        .and(query::<Cursor>())
        .and(with_bc(bc))
        .and_then(handle2(handlers::mempool))
}

fn blocks(bc: BlockchainRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "blocks")
        .and(get())
        .and(query::<Cursor>())
        .and(with_bc(bc))
        .and_then(handle2(handlers::blocks))
}

fn block(bc: BlockchainRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "block" / HexId)
        .and(get())
        .and(with_bc(bc))
        .and_then(handle2(handlers::block))
}

fn tx(bc: BlockchainRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "tx" / HexId)
        .and(get())
        .and(with_bc(bc))
        .and_then(handle2(handlers::tx))
}

fn submit(bc: BlockchainRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "submit")
        .and(post())
        .and(body::json())
        .and(with_bc(bc))
        .and_then(handle2(handlers::submit))
}

fn with_bc(
    bc: BlockchainRef,
) -> impl Filter<Extract = (BlockchainRef,), Error = Infallible> + Clone {
    warp::any().map(move || bc.clone())
}
