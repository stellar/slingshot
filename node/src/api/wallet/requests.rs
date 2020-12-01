use serde::{Deserialize};
use super::super::serde_utils::BigArray;
use crate::api::data::BuildTxAction;

#[derive(Debug, Deserialize)]
pub struct NewWallet {
    pub xpub: Vec<u8>,
    pub label: String,
}

#[derive(Debug, Deserialize)]
pub struct NewReceiver {
    pub flv: [u8; 32],
    pub qty: u64,
    pub exp: u64, // expiration timestamp
}

#[derive(Deserialize)]
pub struct BuildTx {
    pub actions: Vec<BuildTxAction>,
}
