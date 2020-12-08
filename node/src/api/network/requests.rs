use serde::Deserialize;

use crate::api::serde_utils::BigArray;
use crate::api::types::TxHeader;

#[derive(Deserialize)]
pub struct RawTx {
    pub header: TxHeader,
    pub program: Vec<u8>,
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
    pub r1cs_proof: Vec<u8>,
    pub utreexo_proofs: Vec<Vec<u8>>,
}
