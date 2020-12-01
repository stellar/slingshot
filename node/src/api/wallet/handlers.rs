use std::convert::Infallible;
use super::requests;
use crate::api::data::Cursor;
use crate::wallet_manager::WalletRef;
use crate::wallet::Wallet;
use accounts::{AddressLabel, Address};
use keytree::Xpub;
use crate::api::response::{Response, error};
use crate::api::wallet::{responses};
use crate::errors::Error;
use crate::api::wallet::responses::NewAddress;
use curve25519_dalek::scalar::Scalar;

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
pub(super) async fn balance(wallet: WalletRef) -> Result<Response<responses::Balance>, Infallible> {
    let mut wallet_ref = wallet.read().await;
    let wallet = match wallet_ref.wallet_ref() {
        Ok(w) => w,
        Err(_) => return Ok(error::wallet_not_exists()),
    };
    let mut balances = Vec::new();
    wallet.balances().for_each(|balance| {
        balances.push((balance.flavor.to_bytes(), balance.total));
    });
    Ok(Response::ok(responses::Balance { balances }))
}

/// Lists annotated transactions.
pub(super) async fn txs(cursor: Cursor, wallet: WalletRef) -> Result<impl warp::Reply, Infallible> {
    Ok("Lists annotated transactions.")
}

/// Generates a new address.
pub(super) async fn address(wallet: WalletRef) -> Result<Response<NewAddress>, Infallible> {
    let mut wallet_ref = wallet.write().await;
    let update_wallet = |wallet: &mut Wallet| -> Result<Address, crate::Error> {
        Ok(wallet.create_address())
    };
    match wallet_ref.update_wallet(update_wallet) {
        Ok(address) => {
            Ok(Response::ok(NewAddress { address: address.to_string() }))
        },
        Err(crate::Error::WalletNotInitialized) => Ok(error::wallet_not_exists()),
        _ => Ok(error::wallet_updating_error())
    }
}

/// Generates a new receiver.
pub(super) async fn receiver(req: requests::NewReceiver, wallet: WalletRef) -> Result<Response<responses::NewReceiver>, Infallible> {
    let mut wallet_ref = wallet.write().await;
    let update_wallet = |wallet: &mut Wallet| -> Result<accounts::Receiver, crate::Error> {
        let requests::NewReceiver { flv, qty, exp } = req; // TODO: expiration time?
        let (_, receiver) = wallet.create_receiver(zkvm::ClearValue { qty, flv: Scalar::from_bits(flv) });
        Ok(receiver)
    };
    match wallet_ref.update_wallet(update_wallet) {
        Ok(receiver) => {
            Ok(Response::ok(responses::NewReceiver { receiver }))
        },
        Err(crate::Error::WalletNotInitialized) => Ok(error::wallet_not_exists()),
        _ => Ok(error::wallet_updating_error())
    }
}

/// Generates a new receiver.
pub(super) async fn buildtx(req: requests::BuildTx, wallet: WalletRef) -> Result<impl warp::Reply, Infallible> {
    Ok("Generates a new receiver.")
}