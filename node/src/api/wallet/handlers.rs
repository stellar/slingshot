use std::convert::Infallible;
use super::requests;
use crate::api::data::{Cursor, BuildTxAction, AnnotatedTx};
use crate::wallet_manager::WalletRef;
use crate::wallet::{Wallet, TxAction, BuiltTx};
use accounts::{AddressLabel, Address};
use keytree::{Xpub, Xprv};
use crate::api::response::{Response, error};
use crate::api::wallet::{responses};
use crate::errors::Error;
use crate::api::wallet::responses::NewAddress;
use curve25519_dalek::scalar::Scalar;
use zkvm::bulletproofs::BulletproofGens;
use crate::api::data;
use zkvm::{UnsignedTx, TxEntry};
use merlin::Transcript;
use zkvm::encoding::{ExactSizeEncodable, Encodable};

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
pub(super) async fn buildtx(req: requests::BuildTx, wallet: WalletRef) -> Result<Response<responses::BuiltTx>, Infallible> {
    let mut wallet_ref = wallet.write().await;
    let requests::BuildTx { actions } = req;
    let res = actions.clone().into_iter().map(|action| {
        use crate::api::data::BuildTxAction::*;

        match action {
            IssueToAddress(flv, qty, address) => {
                let address = match Address::from_string(&address) {
                    None => return Err(error::invalid_address_label()),
                    Some(addr) => addr
                };
                let clr = zkvm::ClearValue {
                    qty,
                    flv: Scalar::from_bits(flv)
                };
                Ok(TxAction::IssueToAddress(clr, address))
            }
            IssueToReceiver(rec) => Ok(TxAction::IssueToReceiver(rec)),
            TransferToAddress(flv, qty, address) => {
                let address = match Address::from_string(&address) {
                    None => return Err(error::invalid_address_label()),
                    Some(addr) => addr
                };
                let clr = zkvm::ClearValue {
                    qty,
                    flv: Scalar::from_bits(flv)
                };
                Ok(TxAction::TransferToAddress(clr, address))
            }
            TransferToReceiver(rec) => Ok(TxAction::TransferToReceiver(rec)),
            Memo(memo) => Ok(TxAction::Memo(memo)),
        }
    }).collect::<Result<Vec<_>, _>>();

    let actions = match res {
        Ok(actions) => actions,
        Err(resp) => return Ok(resp)
    };

    let mut err = None;

    let update_wallet = |wallet: &mut Wallet| -> Result<BuiltTx, crate::Error> {
        let gens = BulletproofGens::new(256, 1);
        let res = wallet.build_tx(&gens, |builder| {
            for action in actions {
                builder._add_action(action);
            }
        });
        match res {
            Ok(tx) => Ok(tx),
            Err(e) => {
                err = Some(e);
                // Dummy error to specify that giving error when update wallet
                Err(crate::Error::WalletAlreadyExists)
            }
        }
    };
    match wallet_ref.update_wallet(update_wallet) {
        Ok(tx) => {
            let id = (tx.unsigned_tx.txid.0).0;
            let fee = tx.unsigned_tx.txlog.iter().filter_map(|entry| {
                match entry {
                    TxEntry::Fee(fee) => Some(fee),
                    _ => None,
                }
            }).sum::<u64>();

            let xprv = match wallet_ref.read_xprv() {
                Ok(xprv) => xprv,
                Err(_) => return Ok(error::tx_building_error())
            };
            let block_tx = match tx.sign(&xprv) {
                Ok(tx) => tx,
                Err(e) => return Ok(error::wallet_error(e))
            };

            let wid = block_tx.witness_hash().0;

            let raw = hex::encode(block_tx.encode_to_vec());
            let size = block_tx.encoded_size() as u64;

            let tx = data::Tx {
                id,
                wid,
                raw,
                fee,
                size
            };

            Ok(Response::ok(responses::BuiltTx { tx }))
        },
        Err(crate::Error::WalletNotInitialized) => Ok(error::wallet_not_exists()),
        _ => Ok(error::wallet_updating_error())
    }
}