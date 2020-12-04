use crate::api::dto::{AnnotatedTxDTO, TxDTO};
use crate::wallet::SigntxInstruction;
use accounts::Receiver;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NewWallet;

#[derive(Debug, Serialize)]
pub struct Balance {
    pub balances: Vec<([u8; 32], u64)>,
}

#[derive(Serialize)]
pub struct WalletTxs {
    pub cursor: Vec<u8>,
    pub txs: Vec<AnnotatedTxDTO>,
}

#[derive(Serialize)]
pub struct NewAddress {
    pub address: String,
}

#[derive(Serialize)]
pub struct NewReceiver {
    pub receiver: Receiver,
}

#[derive(Serialize)]
pub struct BuiltTx {
    pub tx: TxDTO,
}
