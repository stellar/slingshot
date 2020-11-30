use serde::{Serialize};
use crate::api::data::AnnotatedTx;
use accounts::Receiver;
use crate::wallet::SigntxInstruction;

#[derive(Debug, Serialize)]
pub struct NewWallet {
    id: [u8; 32],
}

#[derive(Debug, Serialize)]
pub struct Balance {
    balances: Vec<([u8; 32], u64)>
}

#[derive(Serialize)]
pub struct WalletTxs {
    cursor: Vec<u8>,
    txs: Vec<AnnotatedTx>
}

#[derive(Serialize)]
pub struct NewAddress {
    address: String,
}

#[derive(Serialize)]
pub struct NewReceiverResponse {
    receiver: Receiver,
}

#[derive(Serialize)]
pub struct BuiltTx {
    tx: AnnotatedTx,
    signing_instructions: Vec<SigntxInstruction>
}
