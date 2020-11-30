use warp::Filter;
use warp::filters::path::param;

use super::requests;

pub fn routes() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    new()
        .or(balance())
        .or(txs())
        .or(address())
        .or(receiver())
        .or(buildtx())
}

fn new() -> impl Filter<Extract = impl warp::Reply, Error = warp::Rejection> + Clone {
    use warp::*;

    path!("v1" / "wallet" / "new")
        .and(post())
        .and(body::json())
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
        .and(query::<requests::Cursor>())
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

mod handlers {
    use std::convert::Infallible;
    use super::requests;

    /// Creates a new wallet
    pub(super) async fn new(request: requests::NewWallet) -> Result<impl warp::Reply, Infallible> {
        Ok("Creates a new wallet")
    }

    /// Returns wallet's balance.
    pub(super) async fn balance(wallet_id: u64) -> Result<impl warp::Reply, Infallible> {
        Ok("Returns wallet's balance.")
    }

    /// Lists annotated transactions.
    pub(super) async fn txs(wallet_id: u64, cursor: requests::Cursor) -> Result<impl warp::Reply, Infallible> {
        Ok("Lists annotated transactions.")
    }

    /// Generates a new address.
    pub(super) async fn address(wallet_id: u64) -> Result<impl warp::Reply, Infallible> {
        Ok("Generates a new address.")
    }

    /// Generates a new receiver.
    pub(super) async fn receiver(wallet_id: u64, req: requests::NewReceiver) -> Result<impl warp::Reply, Infallible> {
        Ok("Generates a new receiver.")
    }

    /// Generates a new receiver.
    pub(super) async fn buildtx(wallet_id: u64, req: requests::BuildTx) -> Result<impl warp::Reply, Infallible> {
        Ok("Generates a new receiver.")
    }
}
