use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;

use crate::contract::Contract;
use crate::errors::VMError;
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

/// MerkleHash represents a step in a Merkle proof of inclusion.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MerkleHash {
    Left([u8; 32]),
    Right([u8; 32]),
}

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
        let t = Transcript::new(b"ZkVM.txid");
        let mut result = [0u8; 32];
        Self::node(t, list, &mut result);
        Self(result)
    }

    fn node(mut t: Transcript, list: &[Entry], result: &mut [u8; 32]) {
        match list.len() {
            0 => Self::empty(t, result),
            1 => Self::leaf(t, &list[0], result),
            n => {
                let k = n.next_power_of_two() / 2;
                let mut righthash = [0u8; 32];
                Self::node(t.clone(), &list[..k], result);
                Self::node(t.clone(), &list[k..], &mut righthash);
                t.commit_bytes(b"L", result);
                t.commit_bytes(b"R", &righthash);
                t.challenge_bytes(b"merkle.node", result);
            }
        }
    }

    fn empty(mut t: Transcript, result: &mut [u8; 32]) {
        t.challenge_bytes(b"merkle.empty", result);
    }

    fn leaf(mut t: Transcript, entry: &Entry, result: &mut [u8; 32]) {
        entry.commit_to_transcript(&mut t);
        t.challenge_bytes(b"merkle.leaf", result);
    }

    /// Computes the Merkle proof of inclusion required to validate an
    /// entry at index i, not including the original item i.
    /// Fails when requested index is out of bounds
    pub fn proof(
        t: Transcript,
        list: &[Entry],
        index: usize,
        result: &mut Vec<MerkleHash>,
    ) -> Result<(), VMError> {
        if index >= list.len() {
            return Err(VMError::InvalidMerkleProof);
        }
        match list.len() {
            0 => Err(VMError::InvalidMerkleProof),
            1 => Ok(()),
            n => {
                let k = n.next_power_of_two() / 2;
                if index >= k {
                    let mut lefthash = [0u8; 32];
                    Self::node(t.clone(), &list[..k], &mut lefthash);
                    result.insert(0, MerkleHash::Left(lefthash));
                    Ok(Self::proof(t, &list[k..], index - k, result)?)
                } else {
                    let mut righthash = [0u8; 32];
                    Self::node(t.clone(), &list[k..], &mut righthash);
                    result.insert(0, MerkleHash::Right(righthash));
                    Ok(Self::proof(t, &list[..k], index, result)?)
                }
            }
        }
    }

    /// Verifies that an entry satisfies the Merkle proof of inclusion
    /// for a given TxID
    pub fn verify_proof(&self, entry: Entry, proof: Vec<MerkleHash>) -> Result<(), VMError> {
        let transcript = Transcript::new(b"ZkVM.txid");
        let mut result = [0u8; 32];
        Self::node(transcript.clone(), &[entry], &mut result);
        for node in proof.iter() {
            let mut t = transcript.clone();
            match node {
                MerkleHash::Left(l) => {
                    t.commit_bytes(b"L", l);
                    t.commit_bytes(b"R", &result);
                    t.challenge_bytes(b"merkle.node", &mut result);
                }
                MerkleHash::Right(r) => {
                    t.commit_bytes(b"L", &result);
                    t.commit_bytes(b"R", r);
                    t.challenge_bytes(b"merkle.node", &mut result);
                }
            }
        }
        if self.0 == result {
            Ok(())
        } else {
            Err(VMError::InvalidMerkleProof)
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
    fn empty() {
        let t = Transcript::new(b"ZkVM.txid");
        let mut result = Vec::new();
        assert!(TxID::proof(t, &[], 0, &mut result).is_err())
    }

    #[test]
    fn invalid_range() {
        let t = Transcript::new(b"ZkVM.txid");
        let mut result = Vec::new();
        assert!(TxID::proof(t, &[], 5, &mut result).is_err())
    }

    #[test]
    fn valid_proof() {
        let (entry, txid, proof) = {
            let t = Transcript::new(b"ZkVM.txid");
            let entries = txlog_helper();
            let mut result = Vec::new();
            let index = 3;
            TxID::proof(t, &entries, index, &mut result).unwrap();
            (entries[index].clone(), TxID::from_log(&entries), result)
        };
        txid.verify_proof(entry, proof).unwrap();
    }

    #[test]
    fn invalid_proof() {
        let (entry, txid, proof) = {
            let t = Transcript::new(b"ZkVM.txid");
            let entries = txlog_helper();
            let mut result = Vec::new();
            let index = 3;
            TxID::proof(t, &entries, index, &mut result).unwrap();
            (entries[index + 1].clone(), TxID::from_log(&entries), result)
        };
        assert!(txid.verify_proof(entry, proof).is_err());
    }
}
