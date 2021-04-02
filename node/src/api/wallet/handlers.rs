use std::convert::{Infallible, TryFrom};

use crate::{
    api::{
        response::{error, Response, ResponseError, ResponseResult},
        types,
        types::Cursor,
        wallet::{requests, responses},
    },
    wallet::{BuiltTx, TxAction, Wallet},
    wallet_manager::WalletRef,
};
use accounts::{Address, AddressLabel};
use curve25519_dalek::scalar::Scalar;
use keytree::{Xprv, Xpub};

/// Creates a new wallet
pub(super) async fn new(
    request: requests::NewWallet,
    wallet: WalletRef,
) -> ResponseResult<responses::NewWallet> {
    let requests::NewWallet { xpub, label } = request;
    let mut wallet_ref = wallet.write().await;
    if wallet_ref.wallet_exists() {
        if let Err(_) = wallet_ref.clear_wallet() {
            return Err(error::cannot_delete_file());
        }
    }
    let label = AddressLabel::new(label).ok_or_else(|| error::invalid_address_label())?;
    let xpub = Xpub::from_bytes(&xpub).ok_or_else(|| error::invalid_xpub())?;

    let new_wallet = Wallet::new(label, xpub);
    wallet_ref
        .initialize_wallet(new_wallet)
        .expect("We previously deleted wallet, there are no other errors when initializing wallet");

    Ok(responses::NewWallet)
}

/// Returns wallet's balance.
pub(super) async fn balance(wallet: WalletRef) -> ResponseResult<responses::Balance> {
    let mut wallet_ref = wallet.read().await;
    let wallet = wallet_ref
        .wallet_ref()
        .map_err(|_| error::wallet_does_not_exist())?;

    let balances = wallet
        .balances()
        .map(|balance| (balance.flavor.to_bytes(), balance.total))
        .collect::<Vec<_>>();

    Ok(responses::Balance { balances })
}

/// Lists annotated transactions.
pub(super) async fn txs(
    _cursor: Cursor,
    _wallet: WalletRef,
) -> ResponseResult<responses::WalletTxs> {
    unimplemented!()
}

/// Generates a new address.
pub(super) async fn address(wallet: WalletRef) -> ResponseResult<responses::NewAddress> {
    let mut wallet_ref = wallet.write().await;
    let update_wallet = |wallet: &mut Wallet| Ok(wallet.create_address());

    match wallet_ref.update_wallet(update_wallet) {
        Ok(address) => Ok(responses::NewAddress {
            address: address.to_string(),
        }),
        Err(crate::Error::WalletNotInitialized) => Err(error::wallet_does_not_exist()),
        _ => Err(error::wallet_updating_error()),
    }
}

/// Generates a new receiver.
pub(super) async fn receiver(
    req: requests::NewReceiver,
    wallet: WalletRef,
) -> ResponseResult<responses::NewReceiver> {
    let mut wallet_ref = wallet.write().await;
    let update_wallet = |wallet: &mut Wallet| {
        let requests::NewReceiver { flv, qty, exp } = req; // TODO: expiration time?
        let receiver_value = zkvm::ClearValue {
            qty,
            flv: Scalar::from_bits(flv),
        };
        let (_, receiver) = wallet.create_receiver(receiver_value);
        Ok(receiver)
    };
    match wallet_ref.update_wallet(update_wallet) {
        Ok(receiver) => Ok(responses::NewReceiver { receiver }),
        Err(crate::Error::WalletNotInitialized) => Err(error::wallet_does_not_exist()),
        _ => Err(error::wallet_updating_error()),
    }
}

/// Generates a new receiver.
pub(super) async fn buildtx(
    req: requests::BuildTx,
    wallet: WalletRef,
) -> ResponseResult<responses::BuiltTx> {
    let mut wallet_ref = wallet.write().await;
    let requests::BuildTx { actions } = req;
    let actions = actions
        .clone()
        .into_iter()
        .map(build_tx_action_to_tx_action)
        .collect::<Result<Vec<_>, _>>()?;

    let mut err = None;

    let update_wallet = |wallet: &mut Wallet| -> Result<BuiltTx, crate::Error> {
        let gens = zkvm::bulletproofs::BulletproofGens::new(256, 1);
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
            let xprv = wallet_ref
                .read_xprv()
                .map_err(|_| error::tx_building_error())?;
            let block_tx = tx.sign(&xprv).map_err(|e| error::wallet_error(e))?;

            let tx = types::Tx::try_from(block_tx).map_err(|_| error::tx_compute_error())?;

            Ok(responses::BuiltTx { tx })
        }
        Err(crate::Error::WalletNotInitialized) => Err(error::wallet_does_not_exist()),
        // This means that we have error while updating wallet
        Err(crate::Error::WalletAlreadyExists) => Err(match err {
            Some(e) => error::wallet_error(e),
            None => error::wallet_updating_error(),
        }),
        _ => Err(error::wallet_updating_error()),
    }
}

fn build_tx_action_to_tx_action(action: types::BuildTxAction) -> Result<TxAction, ResponseError> {
    use crate::api::types::BuildTxAction::*;

    match action {
        IssueToAddress(flv, qty, address) => {
            let address =
                Address::from_string(&address).ok_or_else(|| error::invalid_address_label())?;
            let clr = zkvm::ClearValue {
                qty,
                flv: Scalar::from_bits(flv),
            };
            Ok(TxAction::IssueToAddress(clr, address))
        }
        IssueToReceiver(rec) => Ok(TxAction::IssueToReceiver(rec)),
        TransferToAddress(flv, qty, address) => {
            let address =
                Address::from_string(&address).ok_or_else(|| error::invalid_address_label())?;
            let clr = zkvm::ClearValue {
                qty,
                flv: Scalar::from_bits(flv),
            };
            Ok(TxAction::TransferToAddress(clr, address))
        }
        TransferToReceiver(rec) => Ok(TxAction::TransferToReceiver(rec)),
        Memo(memo) => Ok(TxAction::Memo(memo)),
    }
}
