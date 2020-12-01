mod requests;
mod responses;
mod handlers;

use warp::{Filter, any};
use warp::filters::path::param;
use crate::api::data::Cursor;
use crate::wallet_manager::WalletRef;
use std::convert::Infallible;

pub fn routes(wallet: WalletRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    new(wallet.clone())
        .or(balance())
        .or(txs())
        .or(address())
        .or(receiver())
        .or(buildtx())
}

fn new(wallet: WalletRef) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "new")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet))
        .and_then(handlers::new)
}

fn balance() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / u64 / "balance")
        .and(get())
        .and_then(handlers::balance)
}

fn txs() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / u64 / "txs")
        .and(query::<Cursor>())
        .and(get())
        .and_then(handlers::txs)
}

fn address() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / u64 / "address")
        .and(get())
        .and_then(handlers::address)
}

fn receiver() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / u64 / "receiver")
        .and(post())
        .and(body::json())
        .and_then(handlers::receiver)
}

fn buildtx() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / u64 / "buildtx")
        .and(post())
        .and(body::json())
        .and_then(handlers::buildtx)
}

fn with_wallet(wallet: WalletRef) -> impl Filter<Extract = (WalletRef, ), Error = Infallible> + Clone {
    any().map(move || wallet.clone())
}
