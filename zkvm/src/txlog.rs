use curve25519_dalek::ristretto::CompressedRistretto;
use merlin::Transcript;
use subtle::ConstantTimeEq;

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

/// MerkleNeighbor represents a step in a Merkle proof of inclusion.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MerkleNeighbor {
    Left([u8; 32]),
    Right([u8; 32]),
}

/// MerkleTree represents a node in the Merkle tree, containing either
/// an uncomputed Entry or the precomputed hash.
pub struct MerkleTree {
    size: usize,
    root: MerkleNode,
}

enum MerkleNode {
    Leaf([u8; 32]),
    Node([u8; 32], Box<MerkleNode>, Box<MerkleNode>),
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

    /// Verifies that an entry satisfies the Merkle proof of inclusion
    /// for a given TxID
    pub fn verify_proof(&self, entry: Entry, proof: Vec<MerkleNeighbor>) -> Result<(), VMError> {
        let transcript = Transcript::new(b"ZkVM.txid");
        let mut result = [0u8; 32];
        Self::leaf(transcript.clone(), &entry, &mut result);
        for node in proof.iter() {
            let mut t = transcript.clone();
            match node {
                MerkleNeighbor::Left(l) => {
                    t.commit_bytes(b"L", l);
                    t.commit_bytes(b"R", &result);
                    t.challenge_bytes(b"merkle.node", &mut result);
                }
                MerkleNeighbor::Right(r) => {
                    t.commit_bytes(b"L", &result);
                    t.commit_bytes(b"R", r);
                    t.challenge_bytes(b"merkle.node", &mut result);
                }
            }
        }
        let eq = result.ct_eq(&self.0).unwrap_u8();
        if eq == 1 {
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

impl MerkleTree {
    /// Constructs a new MerkleTree based on the input list of entries.
    pub fn new(list: &[Entry]) -> Option<MerkleTree> {
        if list.len() == 0 {
            return None;
        }
        let t = Transcript::new(b"ZkVM.txid");
        Some(MerkleTree {
            size: list.len(),
            root: MerkleNode::build_tree(t, list),
        })
    }

    /// Builds a proof of inclusion for entry at the given index for the
    /// Merkle tree.
    pub fn proof(&self, index: usize) -> Result<Vec<MerkleNeighbor>, VMError> {
        if index >= self.size {
            return Err(VMError::InvalidMerkleProof);
        }
        let t = Transcript::new(b"ZkVM.txid");
        let mut result = Vec::new();
        self.root.subproof(t, index, self.size, &mut result);
        Ok(result)
    }
}

impl MerkleNode {
    fn build_tree(mut t: Transcript, list: &[Entry]) -> Self {
        match list.len() {
            0 => {
                let mut leaf = [0u8; 32];
                TxID::empty(t, &mut leaf);
                return MerkleNode::Leaf(leaf);
            }
            1 => {
                let mut leaf = [0u8; 32];
                TxID::leaf(t, &list[0], &mut leaf);
                return MerkleNode::Leaf(leaf);
            }
            n => {
                let k = n.next_power_of_two() / 2;
                let mut node = [0u8; 32];
                let left = Self::build_tree(t.clone(), &list[..k]);
                let right = Self::build_tree(t.clone(), &list[k..]);
                t.commit_bytes(b"L", left.hash());
                t.commit_bytes(b"R", right.hash());
                t.challenge_bytes(b"merkle.node", &mut node);
                return MerkleNode::Node(node, Box::new(left), Box::new(right));
            }
        }
    }

    fn subproof(&self, t: Transcript, index: usize, size: usize, result: &mut Vec<MerkleNeighbor>) {
        let k = size.next_power_of_two() / 2;
        if index >= k {
            match self {
                MerkleNode::Node(_, l, r) => {
                    result.insert(0, MerkleNeighbor::Left(*l.hash()));
                    return r.subproof(t, index - k, size - k, result);
                }
                MerkleNode::Leaf(_) => return,
            }
        } else {
            match self {
                MerkleNode::Node(_, l, r) => {
                    result.insert(0, MerkleNeighbor::Right(*r.hash()));
                    return l.subproof(t, index, k, result);
                }
                MerkleNode::Leaf(_) => return,
            }
        }
    }

    /// Returns the hash of a Merkle tree.
    fn hash(&self) -> &[u8; 32] {
        match self {
            MerkleNode::Leaf(h) => h,
            MerkleNode::Node(h, _, _) => h,
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
        assert!(MerkleTree::new(&[]).is_none());
    }

    #[test]
    fn invalid_range() {
        let entries = txlog_helper();
        let root = MerkleTree::new(&entries).unwrap();
        assert!(root.proof(5).is_err())
    }

    #[test]
    fn valid_proof() {
        let (entry, txid, proof) = {
            let entries = txlog_helper();
            let root = MerkleTree::new(&entries).unwrap();
            let index = 3;
            let proof = root.proof(index).unwrap();
            (entries[index].clone(), TxID::from_log(&entries), proof)
        };
        txid.verify_proof(entry, proof).unwrap();
    }

    #[test]
    fn invalid_proof() {
        let (entry, txid, proof) = {
            let entries = txlog_helper();
            let root = MerkleTree::new(&entries).unwrap();
            let index = 3;
            let proof = root.proof(index).unwrap();
            (entries[index + 1].clone(), TxID::from_log(&entries), proof)
        };
        assert!(txid.verify_proof(entry, proof).is_err());
    }
}
