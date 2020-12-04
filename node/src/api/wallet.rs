mod handlers;
mod requests;
mod responses;

use crate::api::dto::Cursor;
use crate::wallet_manager::WalletRef;
use std::convert::Infallible;
use warp::filters::path::param;
use warp::{any, Filter};
use futures::future::NeverError;
use futures::{FutureExt, Future};
use crate::api::response::{ResponseResult, Response};
use crate::api::warp_utils::{handle2, handle1};

pub fn routes(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    new(wallet.clone())
        .or(balance(wallet.clone()))
        .or(txs(wallet.clone()))
        .or(address(wallet.clone()))
        .or(receiver(wallet.clone()))
        .or(buildtx(wallet))
}

fn new(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "new")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet))
        .and_then(handle2(handlers::new))
}

fn balance(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "balance")
        .and(get())
        .and(with_wallet(wallet))
        .and_then(handle1(handlers::balance))
}

fn txs(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "txs")
        .and(query::<Cursor>())
        .and(get())
        .and(with_wallet(wallet))
        .and_then(handle2(handlers::txs))
}

fn address(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "address")
        .and(get())
        .and(with_wallet(wallet))
        .and_then(handle1(handlers::address))
}

fn receiver(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "receiver")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet))
        .and_then(handle2(handlers::receiver))
}

fn buildtx(
    wallet: WalletRef,
) -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "buildtx")
        .and(post())
        .and(body::json())
        .and(with_wallet(wallet))
        .and_then(handle2(handlers::buildtx))
}

fn with_wallet(
    wallet: WalletRef,
) -> impl Filter<Extract = (WalletRef,), Error = Infallible> + Clone {
    any().map(move || wallet.clone())
}
