use serde::{Deserialize};
use super::super::serde_utils::BigArray;
use crate::api::data::BuildTxAction;

#[derive(Debug, Deserialize)]
pub struct NewWallet {
    #[serde(with = "BigArray")]
    xpub: [u8; 64],
    label: String,
}

#[derive(Debug, Deserialize)]
pub struct Cursor {
    // TODO
}

#[derive(Debug, Deserialize)]
pub struct NewReceiver {
    flv: [u8; 32],
    qty: u64,
    exp: u64, // expiration timestamp
}

#[derive(Deserialize)]
pub struct BuildTx {
    actions: Vec<BuildTxAction>,
}
