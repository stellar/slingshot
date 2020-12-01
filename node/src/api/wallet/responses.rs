use serde::{Serialize};
use crate::api::data::AnnotatedTx;
use accounts::Receiver;
use crate::wallet::SigntxInstruction;

#[derive(Debug, Serialize)]
pub struct NewWallet {
    pub id: [u8; 32],
}

#[derive(Debug, Serialize)]
pub struct Balance {
    pub balances: Vec<([u8; 32], u64)>
}

#[derive(Serialize)]
pub struct WalletTxs {
    pub cursor: Vec<u8>,
    pub txs: Vec<AnnotatedTx>
}

#[derive(Serialize)]
pub struct NewAddress {
    pub address: String,
}

#[derive(Serialize)]
pub struct NewReceiverResponse {
    pub receiver: Receiver,
}

#[derive(Serialize)]
pub struct BuiltTx {
    pub tx: AnnotatedTx,
    pub signing_instructions: Vec<SigntxInstruction>
}
