use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;

use crate::contract::Contract;
use crate::merkle::{MerkleItem, MerkleTree};
use crate::transcript::TranscriptProtocol;
use crate::vm::TxHeader;

/// Transaction log. `TxLog` is a type alias for `Vec<Entry>`.
pub type TxLog = Vec<Entry>;

/// Entry in a transaction log
#[derive(Clone, Debug)]
#[allow(missing_docs)]
pub enum Entry {
    Header(TxHeader),
    Issue(CompressedRistretto, CompressedRistretto),
    Retire(CompressedRistretto, CompressedRistretto),
    Input(UTXO),
    Nonce(CompressedRistretto, u64),
    Output(Contract),
    Data(Vec<u8>),
    Import, // TBD: parameters
    Export, // TBD: parameters
}

/// Transaction ID is a unique 32-byte identifier of a transaction
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct TxID(pub [u8; 32]);

/// UTXO is a unique 32-byte identifier of a transaction output
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct UTXO(pub [u8; 32]);

impl UTXO {
    /// Computes UTXO identifier from an output and transaction id.
    pub fn from_output(output: &[u8], txid: &TxID) -> Self {
        let mut t = Transcript::new(b"ZkVM.utxo");
        t.commit_bytes(b"txid", &txid.0);
        t.commit_bytes(b"output", &output);
        let mut utxo = UTXO([0u8; 32]);
        t.challenge_bytes(b"id", &mut utxo.0);
        utxo
    }
}

impl TxID {
    /// Computes TxID from a tx log
    pub fn from_log(list: &[Entry]) -> Self {
        match MerkleTree::new(b"ZkVM.txid", &Entry::to_merkle_item(list)) {
            Some(t) => Self(*t.root()),
            None => Self([0u8; 32]),
        }
    }
}

impl Entry {
    fn commit_to_transcript(&self, t: &mut Transcript) {
        match self {
            Entry::Header(h) => {
                t.commit_u64(b"tx.version", h.version);
                t.commit_u64(b"tx.mintime", h.mintime);
                t.commit_u64(b"tx.maxtime", h.maxtime);
            }
            Entry::Issue(q, f) => {
                t.commit_point(b"issue.q", q);
                t.commit_point(b"issue.f", f);
            }
            Entry::Retire(q, f) => {
                t.commit_point(b"retire.q", q);
                t.commit_point(b"retire.f", f);
            }
            Entry::Input(utxo) => {
                t.commit_bytes(b"input", &utxo.0);
            }
            Entry::Nonce(pred, maxtime) => {
                t.commit_point(b"nonce.p", &pred);
                t.commit_u64(b"nonce.t", *maxtime);
            }
            Entry::Output(contract) => {
                t.commit_bytes(b"output", &contract.to_bytes());
            }
            Entry::Data(data) => {
                t.commit_bytes(b"data", data);
            }
            Entry::Import => {
                // TBD: commit parameters
                unimplemented!()
            }
            Entry::Export => {
                // TBD: commit parameters
                unimplemented!()
            }
        }
    }

    fn to_merkle_item(entries: &[Entry]) -> Vec<&MerkleItem> {
        entries.iter().map(|e| e as &MerkleItem).collect::<Vec<_>>()
    }
}

impl MerkleItem for Entry {
    fn commit(&self, t: &mut Transcript) {
        self.commit_to_transcript(t);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txlog_helper() -> Vec<Entry> {
        vec![
            Entry::Header(TxHeader {
                mintime: 0,
                maxtime: 0,
                version: 0,
            }),
            Entry::Issue(
                CompressedRistretto::from_slice(&[0u8; 32]),
                CompressedRistretto::from_slice(&[1u8; 32]),
            ),
            Entry::Nonce(CompressedRistretto::from_slice(&[1u8; 32]), 0u64),
            Entry::Nonce(CompressedRistretto::from_slice(&[2u8; 32]), 1u64),
            Entry::Nonce(CompressedRistretto::from_slice(&[3u8; 32]), 2u64),
        ]
    }

    #[test]
    fn valid_txid_proof() {
        let (entry, txid, proof) = {
            let entries = txlog_helper();
            let root = MerkleTree::new(b"ZkVM.txid", &Entry::to_merkle_item(&entries)).unwrap();
            let index = 3;
            let proof = root.proof(index).unwrap();
            (entries[index].clone(), TxID::from_log(&entries), proof)
        };
        MerkleTree::verify_proof(b"ZkVM.txid", &entry, proof, &txid.0).unwrap();
    }

    #[test]
    fn invalid_txid_proof() {
        let (entry, txid, proof) = {
            let entries = txlog_helper();
            let root = MerkleTree::new(b"ZkVM.txid", &Entry::to_merkle_item(&entries)).unwrap();
            let index = 3;
            let proof = root.proof(index).unwrap();
            (entries[index + 1].clone(), TxID::from_log(&entries), proof)
        };
        assert!(MerkleTree::verify_proof(b"ZkVM.txid", &entry, proof, &txid.0).is_err());
    }
}
