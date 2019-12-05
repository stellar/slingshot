use core::borrow::Borrow;
use merlin::Transcript;
use std::fmt;
use subtle::ConstantTimeEq;

use crate::errors::VMError;

/// Merkle hash of a node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash(pub [u8; 32]);
serialize_bytes32!(Hash);

/// MerkleItem defines an item in the Merkle tree.
pub trait MerkleItem: Sized {
    /// Commits the hash of the item to Transcript.
    fn commit(&self, t: &mut Transcript);
}

impl<T> MerkleItem for &T
where
    T: MerkleItem,
{
    fn commit(&self, t: &mut Transcript) {
        T::commit(*self, t)
    }
}

/// MerkleNeighbor is a step in a Merkle proof of inclusion.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum MerkleNeighbor {
    /// Hash of left subtree
    Left(Hash),
    /// Hash of right subtree
    Right(Hash),
}

/// Merkle tree of hashes with a given size.
pub struct MerkleTree {
    size: usize,
    label: &'static [u8],
    root: MerkleNode,
}

enum MerkleNode {
    Empty(Hash),
    Leaf(Hash),
    Node(Hash, Box<MerkleNode>, Box<MerkleNode>),
}

/// Efficient builder of the merkle root.
/// See `MerkleTree::build_root`
pub struct MerkleRootBuilder {
    transcript: Transcript,
    roots: Vec<Option<Hash>>,
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash({})", hex::encode(&self.0))
        // Without hex crate we'd do this, but it outputs comma-separated numbers: [aa, 11, 5a, ...]
        // write!(f, "{:x?}", &self.0)
    }
}

impl MerkleTree {
    /// Prepares a root builder to compute the root iteratively.
    pub fn build_root(label: &'static [u8]) -> MerkleRootBuilder {
        MerkleRootBuilder {
            transcript: Transcript::new(label),
            roots: Vec::new(),
        }
    }

    /// Constructs a new MerkleTree based on the input list of entries.
    pub fn build<M: MerkleItem>(label: &'static [u8], list: &[M]) -> Self {
        let t = Transcript::new(label);
        let root = Self::build_tree(t, list);
        MerkleTree {
            size: list.len(),
            label,
            root,
        }
    }

    /// Returns the root hash of the Merkle tree.
    pub fn hash(&self) -> &Hash {
        self.root.hash()
    }

    /// Builds the Merkle path of inclusion for the entry at the given index in the
    /// Merkle tree.
    pub fn create_path(&self, index: usize) -> Result<Vec<MerkleNeighbor>, VMError> {
        if index >= self.size {
            return Err(VMError::InvalidMerkleProof);
        }
        let t = Transcript::new(self.label);
        let mut result = Vec::new();
        self.root.subpath(t, index, self.size, &mut result)?;
        Ok(result)
    }

    /// Computes the Merkle root, given the Merkle path.
    pub fn compute_root_from_path<M: MerkleItem>(
        label: &'static [u8],
        entry: &M,
        proof: &Vec<MerkleNeighbor>,
    ) -> Hash {
        let transcript = Transcript::new(label);
        let mut result = Hash::default();
        Self::leaf(transcript.clone(), entry, &mut result);
        for node in proof.iter() {
            let mut t = transcript.clone();
            match node {
                MerkleNeighbor::Left(l) => {
                    t.append_message(b"L", l);
                    t.append_message(b"R", &result);
                    t.challenge_bytes(b"merkle.node", &mut result);
                }
                MerkleNeighbor::Right(r) => {
                    t.append_message(b"L", &result);
                    t.append_message(b"R", r);
                    t.challenge_bytes(b"merkle.node", &mut result);
                }
            }
        }
        result
    }

    /// Verifies the Merkle path for an item given the path and the Merkle root.
    pub fn verify_path<M: MerkleItem>(
        label: &'static [u8],
        entry: &M,
        proof: Vec<MerkleNeighbor>,
        root: &Hash,
    ) -> Result<(), VMError> {
        let result = Self::compute_root_from_path(label, entry, &proof);
        if result.ct_eq(root).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(VMError::InvalidMerkleProof)
        }
    }

    /// Returns a root of an empty tree.
    /// This is provided so the user does not have to fill in complex type annotations
    /// when the empty container is untyped.
    pub fn empty_root(label: &'static [u8]) -> Hash {
        let t = Transcript::new(label);
        let mut h = Hash::default();
        Self::empty(t, &mut h);
        h
    }

    /// Builds and returns the root hash of a Merkle tree constructed from
    /// the supplied list.
    pub fn root<M, I>(label: &'static [u8], list: I) -> Hash
    where
        M: MerkleItem,
        I: IntoIterator<Item = M>,
    {
        list.into_iter()
            .fold(Self::build_root(label), |mut builder, item| {
                builder.append(item.borrow());
                builder
            })
            .root()
    }

    fn build_tree<M: MerkleItem>(t: Transcript, list: &[M]) -> MerkleNode {
        let mut h = Hash::default();
        match list.len() {
            0 => {
                Self::empty(t, &mut h);
                MerkleNode::Empty(h)
            }
            1 => {
                Self::leaf(t, &list[0], &mut h);
                MerkleNode::Leaf(h)
            }
            n => {
                let k = n.next_power_of_two() / 2;
                let left = Self::build_tree(t.clone(), &list[..k]);
                let right = Self::build_tree(t.clone(), &list[k..]);
                let mut hash = *right.hash();
                Self::intermediate(t, &left.hash(), &mut hash);
                MerkleNode::Node(hash, Box::new(left), Box::new(right))
            }
        }
    }

    fn intermediate(mut t: Transcript, left: &Hash, right: &mut Hash) {
        t.append_message(b"L", left);
        t.append_message(b"R", right);
        t.challenge_bytes(b"merkle.node", right);
    }

    fn empty(mut t: Transcript, result: &mut Hash) {
        t.challenge_bytes(b"merkle.empty", result);
    }

    fn leaf<M: MerkleItem>(mut t: Transcript, entry: &M, result: &mut Hash) {
        entry.commit(&mut t);
        t.challenge_bytes(b"merkle.leaf", result);
    }
}

impl MerkleRootBuilder {
    /// Appends an item to the merkle tree.
    pub fn append<M: MerkleItem>(&mut self, item: &M) {
        let mut level = 0usize;
        let mut current_hash = Hash::default();
        MerkleTree::leaf(self.transcript.clone(), item, &mut current_hash);
        while self.roots.len() > level {
            if let Some(left_hash) = self.roots[level] {
                // Found an existing slot at the current level:
                // merge with the current hash and liberate the slot.
                MerkleTree::intermediate(self.transcript.clone(), &left_hash, &mut current_hash);
                self.roots[level] = None;
            } else {
                // Found an empty slot - fill it with the current hash and return
                self.roots[level] = Some(current_hash);
                return;
            }
            level += 1;
        }
        // Did not find an existing slot - push a new one.
        self.roots.push(Some(current_hash));
    }

    /// Compute the merkle root.
    pub fn root(self) -> Hash {
        let t = self.transcript;
        self.roots
            .into_iter()
            .fold(None, |maybe_current, maybe_root| {
                if let Some(mut r) = maybe_current {
                    if let Some(l) = maybe_root {
                        // if we have a pair of roots, merge them in a new root.
                        MerkleTree::intermediate(t.clone(), &l, &mut r);
                    } else {
                        // if we don't yet have a root, keep the current one unchanged.
                    }
                    Some(r)
                } else {
                    // while we don't have any current root, keep
                    maybe_root
                }
            })
            .unwrap_or_else(|| {
                // If no root was computed (the roots vector was empty),
                // return a hash for the "empty" set.
                let mut hash = Hash::default();
                MerkleTree::empty(t.clone(), &mut hash);
                hash
            })
    }
}

impl MerkleNode {
    fn subpath(
        &self,
        t: Transcript,
        index: usize,
        size: usize,
        result: &mut Vec<MerkleNeighbor>,
    ) -> Result<(), VMError> {
        match self {
            MerkleNode::Empty(_) => Err(VMError::InvalidMerkleProof),
            MerkleNode::Leaf(_) => Ok(()),
            MerkleNode::Node(_, l, r) => {
                let k = size.next_power_of_two() / 2;
                if index >= k {
                    result.insert(0, MerkleNeighbor::Left(l.hash().clone()));
                    r.subpath(t, index - k, size - k, result)
                } else {
                    result.insert(0, MerkleNeighbor::Right(r.hash().clone()));
                    return l.subpath(t, index, k, result);
                }
            }
        }
    }

    /// Returns the hash of a Merkle tree.
    fn hash(&self) -> &Hash {
        match self {
            MerkleNode::Empty(h) => &h,
            MerkleNode::Leaf(h) => &h,
            MerkleNode::Node(h, _, _) => &h,
        }
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl core::ops::Deref for Hash {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl core::ops::DerefMut for Hash {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestItem(u64);

    impl MerkleItem for TestItem {
        fn commit(&self, t: &mut Transcript) {
            t.append_u64(b"item", self.0)
        }
    }

    fn test_items(num: usize) -> Vec<TestItem> {
        let mut items = Vec::with_capacity(num);
        for i in 0..num {
            items.push(TestItem(i as u64))
        }
        items
    }

    macro_rules! assert_proof {
        ($num:ident, $idx:ident) => {
            let (item, root, proof) = {
                let items = test_items(*$num as usize);
                let tree = MerkleTree::build(b"test", &items);
                let proof = tree.create_path(*$idx as usize).unwrap();
                (items[*$idx as usize].clone(), tree.hash().clone(), proof)
            };
            MerkleTree::verify_path(b"test", &item, proof, &root).unwrap();
        };
    }

    macro_rules! assert_proof_err {
        ($num:ident, $idx:ident, $wrong_idx:ident) => {
            let (item, root, proof) = {
                let items = test_items(*$num as usize);
                let tree = MerkleTree::build(b"test", &items);
                let proof = tree.create_path(*$idx as usize).unwrap();
                (
                    items[*$wrong_idx as usize].clone(),
                    tree.hash().clone(),
                    proof,
                )
            };
            assert!(MerkleTree::verify_path(b"test", &item, proof, &root).is_err());
        };
    }

    #[test]
    fn invalid_range() {
        let entries = test_items(5);
        let root = MerkleTree::build(b"test", &entries);
        assert!(root.create_path(7).is_err())
    }

    #[test]
    fn valid_proofs() {
        let tests = [(10, 7), (11, 3), (12, 0), (5, 3), (25, 9)];
        for (num, idx) in tests.iter() {
            assert_proof!(num, idx);
        }
    }

    #[test]
    fn invalid_proofs() {
        let tests = [(10, 7, 8), (11, 3, 5), (12, 0, 2), (5, 3, 1), (25, 9, 8)];
        for (num, idx, wrong_idx) in tests.iter() {
            assert_proof_err!(num, idx, wrong_idx);
        }
    }
}
