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

/// MerkleRoot defines the root of a Merkle tree.
pub struct MerkleRoot {
    root: MerkleNode,
    size: usize,
}

/// MerkleNode represents a precomputed node in the Merkle tree
/// for easily computing proofs of inclusion.
struct MerkleNode {
    left: Option<Box<MerkleNode>>,
    right: Option<Box<MerkleNode>>,
    node: [u8; 32],
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

    /// Builds a precomputed Merkle tree for the entries.
    pub fn build_tree(list: &[Entry]) -> (Self, MerkleRoot) {
        let t = Transcript::new(b"ZkVM.txid");
        let root = Self::build_node(t, list);
        (
            TxID(root.node),
            MerkleRoot {
                root,
                size: list.len(),
            },
        )
    }

    fn build_node(mut t: Transcript, list: &[Entry]) -> MerkleNode {
        match list.len() {
            0 => {
                let mut leaf = [0u8; 32];
                Self::empty(t, &mut leaf);
                return MerkleNode {
                    node: leaf,
                    left: None,
                    right: None,
                };
            }
            1 => {
                let mut leaf = [0u8; 32];
                Self::leaf(t, &list[0], &mut leaf);
                return MerkleNode {
                    node: leaf,
                    left: None,
                    right: None,
                };
            }
            n => {
                let k = n.next_power_of_two() / 2;
                let mut node = [0u8; 32];
                let left = Self::build_node(t.clone(), &list[..k]);
                let right = Self::build_node(t.clone(), &list[k..]);
                t.commit_bytes(b"L", &left.node);
                t.commit_bytes(b"R", &right.node);
                t.challenge_bytes(b"merkle.node", &mut node);
                return MerkleNode {
                    node: node,
                    left: Some(Box::new(left)),
                    right: Some(Box::new(right)),
                };
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

impl MerkleRoot {
    pub fn proof(&self, index: usize) -> Result<Vec<MerkleHash>, VMError> {
        if index >= self.size {
            println!("size invalid");
            return Err(VMError::InvalidMerkleProof);
        }
        let t = Transcript::new(b"ZkVM.txid");
        let mut result = Vec::new();
        Self::subproof(t, index, self.size, &self.root, &mut result);
        Ok(result)
    }

    fn subproof(
        t: Transcript,
        index: usize,
        length: usize,
        root: &MerkleNode,
        result: &mut Vec<MerkleHash>,
    ) {
        let k = length.next_power_of_two() / 2;
        if index >= k {
            match &root.left {
                Some(l) => result.insert(0, MerkleHash::Left(l.node)),
                None => return,
            };
            match &root.right {
                Some(r) => {
                    return Self::subproof(t, index - k, length - k, &r, result);
                }
                None => return,
            };
        } else {
            match &root.right {
                Some(r) => result.insert(0, MerkleHash::Right(r.node)),
                None => return,
            };
            match &root.left {
                Some(l) => {
                    return Self::subproof(t, index, k, &l, result);
                }
                None => return,
            };
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
        let (_, root) = TxID::build_tree(&[]);
        assert!(root.proof(0).is_err())
    }

    #[test]
    fn invalid_range() {
        let entries = txlog_helper();
        let (_, root) = TxID::build_tree(&entries);
        assert!(root.proof(5).is_err())
    }

    #[test]
    fn valid_proof() {
        let (entry, txid, proof) = {
            let entries = txlog_helper();
            let (txid, root) = TxID::build_tree(&entries);
            let index = 3;
            let proof = root.proof(index).unwrap();
            (entries[index].clone(), txid, proof)
        };
        txid.verify_proof(entry, proof).unwrap();
    }

    #[test]
    fn invalid_proof() {
        let (entry, txid, proof) = {
            let entries = txlog_helper();
            let (txid, root) = TxID::build_tree(&entries);
            let index = 3;
            let proof = root.proof(index).unwrap();
            (entries[index + 1].clone(), txid, proof)
        };
        assert!(txid.verify_proof(entry, proof).is_err());
    }
}
