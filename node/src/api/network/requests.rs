use serde::Deserialize;
use zkvm::TxHeader;
use crate::api::serde_utils::BigArray;

#[derive(Deserialize)]
pub struct RawTx {
    header: TxHeader,
    program: Vec<u8>,
    #[serde(with = "BigArray")]
    signature: [u8; 64],
    r1cs_proof: Vec<u8>,
    utreexo_proofs: Vec<Vec<u8>>,
}
