use serde::Deserialize;
use zkvm::TxHeader;
use crate::api::serde_utils::BigArray;

#[derive(Deserialize)]
pub struct RawTx {
    pub header: TxHeader,
    pub program: Vec<u8>,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub r1cs_proof: Vec<u8>,
    pub utreexo_proofs: Vec<Vec<u8>>,
}
