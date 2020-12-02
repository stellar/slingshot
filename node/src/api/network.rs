mod handlers;
mod requests;
mod responses;

use crate::api::data::{Cursor, HexId};
use warp::Filter;

pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    status()
        .or(mempool())
        .or(blocks())
        .or(block())
        .or(tx())
        .or(submit())
}

fn status() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "status")
        .and(get())
        .and_then(handlers::status)
}

fn mempool() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "mempool")
        .and(get())
        .and(query::<Cursor>())
        .and_then(handlers::mempool)
}

fn blocks() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "blocks")
        .and(get())
        .and(query::<Cursor>())
        .and_then(handlers::blocks)
}

fn block() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "block" / HexId)
        .and(get())
        .and_then(handlers::block)
}

fn tx() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "tx" / HexId)
        .and(get())
        .and_then(handlers::tx)
}

fn submit() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "network" / "submit")
        .and(post())
        .and(body::json())
        .and_then(handlers::submit)
}
