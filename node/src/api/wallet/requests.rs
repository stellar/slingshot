use super::super::serde_utils::BigArray;
use crate::api::dto::BuildTxActionDTO;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct NewWallet {
    pub xpub: Vec<u8>,
    pub label: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NewReceiver {
    pub flv: [u8; 32],
    pub qty: u64,
    pub exp: u64, // expiration timestamp
}

#[derive(Serialize, Deserialize)]
pub struct BuildTx {
    pub actions: Vec<BuildTxActionDTO>,
}
