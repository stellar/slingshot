use merlin::Transcript;
use subtle::ConstantTimeEq;

use crate::errors::VMError;

pub trait MerkleItem {
    fn commit(&self, t: &mut Transcript);
}

/// MerkleNeighbor represents a step in a Merkle proof of inclusion.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MerkleNeighbor {
    Left([u8; 32]),
    Right([u8; 32]),
}

/// MerkleTree represents a Merkle tree of hashes with a given size.
pub struct MerkleTree {
    size: usize,
    label: &'static [u8],
    root: MerkleNode,
}

enum MerkleNode {
    Leaf([u8; 32]),
    Node([u8; 32], Box<MerkleNode>, Box<MerkleNode>),
}

impl MerkleTree {
    /// Constructs a new MerkleTree based on the input list of entries.
    pub fn new(label: &'static [u8], list: &[&MerkleItem]) -> Option<MerkleTree> {
        if list.len() == 0 {
            return None;
        }
        let t = Transcript::new(label);
        Some(MerkleTree {
            size: list.len(),
            label,
            root: Self::build_tree(t, list),
        })
    }

    /// Builds a proof of inclusion for entry at the given index for the Merkle tree.
    pub fn proof(&self, index: usize) -> Result<Vec<MerkleNeighbor>, VMError> {
        if index >= self.size {
            return Err(VMError::InvalidMerkleProof);
        }
        let t = Transcript::new(self.label);
        let mut result = Vec::new();
        self.root.subproof(t, index, self.size, &mut result);
        Ok(result)
    }

    pub fn verify_proof(
        label: &'static [u8],
        entry: &MerkleItem,
        proof: Vec<MerkleNeighbor>,
        root: &[u8; 32],
    ) -> Result<(), VMError> {
        let transcript = Transcript::new(label);
        let mut result = [0u8; 32];
        Self::leaf(transcript.clone(), entry, &mut result);
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
        if result.ct_eq(root).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(VMError::InvalidMerkleProof)
        }
    }

    /// Returns the root hash of the Merkle tree
    pub fn root(&self) -> &[u8; 32] {
        self.root.hash()
    }

    fn build_tree(mut t: Transcript, list: &[&MerkleItem]) -> MerkleNode {
        match list.len() {
            0 => {
                let mut leaf = [0u8; 32];
                Self::empty(t, &mut leaf);
                return MerkleNode::Leaf(leaf);
            }
            1 => {
                let mut leaf = [0u8; 32];
                Self::leaf(t, list[0], &mut leaf);
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

    fn node(mut t: Transcript, list: &[&MerkleItem], result: &mut [u8; 32]) {
        match list.len() {
            0 => Self::empty(t, result),
            1 => Self::leaf(t, list[0], result),
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

    fn leaf(mut t: Transcript, entry: &MerkleItem, result: &mut [u8; 32]) {
        entry.commit(&mut t);
        t.challenge_bytes(b"merkle.leaf", result);
    }
}

impl MerkleNode {
    fn subproof(&self, t: Transcript, index: usize, size: usize, result: &mut Vec<MerkleNeighbor>) {
        match self {
            MerkleNode::Leaf(_) => return,
            MerkleNode::Node(_, l, r) => {
                let k = size.next_power_of_two() / 2;
                if index >= k {
                    result.insert(0, MerkleNeighbor::Left(*l.hash()));
                    return r.subproof(t, index - k, size - k, result);
                } else {
                    result.insert(0, MerkleNeighbor::Right(*r.hash()));
                    return l.subproof(t, index, k, result);
                }
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
