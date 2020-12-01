use std::convert::Infallible;
use super::requests;
use crate::api::data::Cursor;
use crate::wallet_manager::WalletRef;
use crate::wallet::Wallet;
use accounts::AddressLabel;
use keytree::Xpub;
use crate::api::response::{Response, error};
use crate::api::wallet::{responses};

/// Creates a new wallet
pub(super) async fn new(request: requests::NewWallet, wallet: WalletRef) -> Result<Response<responses::NewWallet>, Infallible> {
    let requests::NewWallet { xpub, label } = request;
    let mut wallet_ref = wallet.write().await;
    if wallet_ref.wallet_exists() {
        if let Err(_) = wallet_ref.clear_wallet() {
            return Ok(error::cannot_delete_file());
        }
    }
    let label = match AddressLabel::new(label) {
        Some(label) => label,
        None => return Ok(error::invalid_address_label()),
    };
    let xpub = match Xpub::from_bytes(&xpub) {
        Some(label) => label,
        None => return Ok(error::invalid_xpub()),
    };
    let new_wallet = Wallet::new(label, xpub);
    wallet_ref.initialize_wallet(new_wallet).expect("We previously deleted wallet, there are no other errors when initializing wallet");

    Ok(Response::ok(responses::NewWallet))
}

/// Returns wallet's balance.
pub(super) async fn balance() -> Result<impl warp::Reply, Infallible> {
    Ok("Returns wallet's balance.")
}

/// Lists annotated transactions.
pub(super) async fn txs(cursor: Cursor) -> Result<impl warp::Reply, Infallible> {
    Ok("Lists annotated transactions.")
}

/// Generates a new address.
pub(super) async fn address() -> Result<impl warp::Reply, Infallible> {
    Ok("Generates a new address.")
}

/// Generates a new receiver.
pub(super) async fn receiver(req: requests::NewReceiver) -> Result<impl warp::Reply, Infallible> {
    Ok("Generates a new receiver.")
}

/// Generates a new receiver.
pub(super) async fn buildtx(req: requests::BuildTx) -> Result<impl warp::Reply, Infallible> {
    Ok("Generates a new receiver.")
}