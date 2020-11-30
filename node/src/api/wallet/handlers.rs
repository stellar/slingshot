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