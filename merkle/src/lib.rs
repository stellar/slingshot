#![deny(missing_docs)]

//! API for operations on merkle binary trees.
use core::marker::PhantomData;
use merlin::Transcript;
use readerwriter::*;
use serde::{Deserialize, Serialize};
use std::fmt;
use subtle::ConstantTimeEq;

/// Merkle hash of a node.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Hash(pub [u8; 32]);

/// MerkleItem defines an item in the Merkle tree.
pub trait MerkleItem: Sized {
    /// Commits the hash of the item to Transcript.
    fn commit(&self, t: &mut Transcript);
}

/// Precomputed hash instance.
pub struct Hasher<M: MerkleItem> {
    t: Transcript,
    phantom: PhantomData<M>,
}

/// Merkle tree of hashes with a given size.
pub struct MerkleTree;

/// Efficient builder of the merkle root.
/// See `MerkleTree::build_root`
pub struct MerkleRootBuilder<M: MerkleItem> {
    hasher: Hasher<M>,
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
    /// Builds and returns the root hash of a Merkle tree constructed from
    /// the supplied list.
    pub fn root<M, I>(label: &'static [u8], list: I) -> Hash
    where
        M: MerkleItem,
        I: IntoIterator<Item = M>,
    {
        list.into_iter()
            .fold(Self::build_root(label), |mut builder, item| {
                builder.append(&item);
                builder
            })
            .root()
    }

    /// Prepares a root builder to compute the root iteratively.
    pub fn build_root<M: MerkleItem>(label: &'static [u8]) -> MerkleRootBuilder<M> {
        MerkleRootBuilder {
            hasher: Hasher::new(label),
            roots: Vec::new(),
        }
    }

    /// Returns a root of an empty tree.
    /// This is provided so the user does not have to fill in complex type annotations
    /// when the empty container is untyped.
    pub fn empty_root(label: &'static [u8]) -> Hash {
        Hasher::<()>::new(label).empty()
    }

    /// Connects roots of perfect binary trees, enumerated from low to high,
    /// into a merkle root of an imperfect tree.
    pub fn connect_perfect_roots<M: MerkleItem>(
        roots: impl IntoIterator<Item = Hash>,
        hasher: &Hasher<M>,
    ) -> Hash {
        roots
            .into_iter()
            .fold(None, |maybe_current, root| {
                maybe_current
                    .map(|curr| hasher.intermediate(&root, &curr))
                    .or(Some(root))
            })
            .unwrap_or_else(|| {
                // If no root was computed (the roots vector was empty),
                // return a hash for the "empty" set.
                hasher.empty()
            })
    }
}

impl<M: MerkleItem> MerkleRootBuilder<M> {
    /// Appends an item to the merkle tree.
    pub fn append(&mut self, item: &M) {
        let mut level = 0usize;
        let mut current_hash = self.hasher.leaf(item);
        while self.roots.len() > level {
            if let Some(left_hash) = self.roots[level].take() {
                // Found an existing slot at the current level:
                // merge with the current hash. Slot is liberated via Option::take().
                current_hash = self.hasher.intermediate(&left_hash, &current_hash);
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
    pub fn root(&self) -> Hash {
        MerkleTree::connect_perfect_roots(self.roots.iter().filter_map(|r| *r), &self.hasher)
    }

    /// Resets the builder to the clean state,
    /// keeping allocated memory.
    /// Use this to recycle allocated memoy when you need to compute multiple roots.
    pub fn reset(&mut self) {
        self.roots.truncate(0);
    }
}

/// The only reason for this impl is to compute an empty hash and
/// keep that implementation in one place (Hasher), generic over the item type:
/// `Hasher::<()>::new(label).empty()`.
impl MerkleItem for () {
    fn commit(&self, t: &mut Transcript) {
        t.append_message(b"", b"");
    }
}

impl<T> MerkleItem for &T
where
    T: MerkleItem,
{
    fn commit(&self, t: &mut Transcript) {
        T::commit(*self, t)
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

impl<M: MerkleItem> Clone for Hasher<M> {
    fn clone(&self) -> Self {
        Self {
            t: self.t.clone(),
            phantom: self.phantom,
        }
    }
}

impl<M: MerkleItem> Hasher<M> {
    /// Creates a new hasher instance.
    pub fn new(label: &'static [u8]) -> Self {
        Self {
            t: Transcript::new(label),
            phantom: PhantomData,
        }
    }

    /// Computes hash of the leaf node in a merkle tree.
    pub fn leaf(&self, item: &M) -> Hash {
        let mut t = self.t.clone();
        item.commit(&mut t);
        let mut hash = Hash::default();
        t.challenge_bytes(b"merkle.leaf", &mut hash);
        hash
    }

    /// Computes hash of the inner node in a merkle tree (that contains left/right child nodes).
    pub fn intermediate(&self, left: &Hash, right: &Hash) -> Hash {
        let mut t = self.t.clone();
        t.append_message(b"L", &left);
        t.append_message(b"R", &right);
        let mut hash = Hash::default();
        t.challenge_bytes(b"merkle.node", &mut hash);
        hash
    }

    /// Computes a hash of an empty tree.
    pub fn empty(&self) -> Hash {
        let mut t = self.t.clone();
        let mut hash = Hash::default();
        t.challenge_bytes(b"merkle.empty", &mut hash);
        hash
    }
}

/// Absolute position of an item in the tree.
pub type Position = u64;

/// Merkle proof of inclusion of a node in a `Forest`.
/// The exact tree is determined by the `position`, an absolute position of the item
/// within the set of all items in the forest.
/// Neighbors are counted from lowest to the highest.
/// Left/right position of the neighbor is determined by the appropriate bit in `position`.
/// (Lowest bit=1 means the first neighbor is to the left of the node.)
/// `path` is None if this proof is for a newly added item that has no merkle path yet.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Path {
    /// Position of the item under this path.
    ///
    /// IMPORTANT: path.position is not necessarily the same as the global index.
    /// it acts as a list of sides for the neighoring hashes.  
    ///
    /// E.g. in a 7-item tree, the last item `g` has position "3" (11 in binary) because it has
    /// two left neighbors (z,w), but item `d` also has position "3" (011 in binary),
    /// because its first neighbors are also on the left (c, x),
    /// but there's also one more right-side neighbor `u`.
    /// ```ascii
    ///
    ///        r
    ///       / \
    ///      w   u
    ///     /|   | \
    ///    x y   z  \
    ///   /| |\  |\  \  
    ///  a b c d e f  g
    /// ```
    pub position: Position,
    /// List of neighbor hashes for this path.
    pub neighbors: Vec<Hash>,
}

/// Side of the neighbour produced by the `Directions` iterator.
#[derive(Copy, Clone, PartialEq, Debug)]
pub enum Side {
    /// Indicates that the item is to the left of its neighbor.
    Left,
    /// Indicates that the item is to the right of its neighbor.
    Right,
}

impl Side {
    /// Orders (current, neighbor) pair of nodes as (left, right)
    /// Alternative meaning in context of a path traversal: orders (left, right) pair of nodes as (main, neighbor)
    pub fn order<T>(self, a: T, b: T) -> (T, T) {
        match self {
            Side::Left => (a, b),
            Side::Right => (b, a),
        }
    }

    fn from_bit(bit: u8) -> Self {
        match bit {
            0 => Side::Left,
            _ => Side::Right,
        }
    }
}

impl Default for Path {
    fn default() -> Path {
        Path {
            position: 0,
            neighbors: Vec::new(),
        }
    }
}

impl Path {
    /// Iterates over elements of the path.
    pub fn iter(&self) -> impl DoubleEndedIterator<Item = (Side, &Hash)> + ExactSizeIterator {
        self.directions().zip(self.neighbors.iter())
    }

    fn directions(&self) -> Directions {
        Directions {
            position: self.position,
            depth: self.neighbors.len(),
        }
    }

    /// Creates a new path by hashing the merkle tree on the fly
    /// without allocating the entire tree.
    pub fn new<M: MerkleItem>(list: &[M], item_index: usize, hasher: &Hasher<M>) -> Option<Self> {
        fn root<M: MerkleItem>(list: &[M], builder: &mut MerkleRootBuilder<M>) -> Hash {
            builder.reset();
            list.iter()
                .fold(builder, |bldr, item| {
                    bldr.append(item);
                    bldr
                })
                .root()
        }
        fn fill_neighbors<M: MerkleItem>(
            list: &[M],
            index: usize,
            path: &mut Path,
            hasher: &Hasher<M>,
            builder: &mut MerkleRootBuilder<M>,
        ) {
            if list.len() < 2 {
                // if we have a tree to talk about
                return;
            }
            let k = list.len().next_power_of_two() / 2;
            // Note: path.position is not necessarily the same as the global index.
            // See documentation for `Path::position`.
            path.position = path.position << 1;
            if index >= k {
                path.position = path.position | 1;
                path.neighbors.insert(0, root(&list[..k], builder));
                fill_neighbors(&list[k..], index - k, path, hasher, builder);
            } else {
                path.neighbors.insert(0, root(&list[k..], builder));
                fill_neighbors(&list[..k], index, path, hasher, builder);
            }
        }
        if item_index > list.len() {
            return None;
        }
        let mut builder = MerkleRootBuilder {
            hasher: hasher.clone(),
            roots: Vec::new(),
        };
        let mut path = Path::default();
        fill_neighbors(list, item_index, &mut path, hasher, &mut builder);
        Some(path)
    }

    /// Computes the root hash for the item with this path.
    pub fn compute_root<M: MerkleItem>(&self, item: &M, hasher: &Hasher<M>) -> Hash {
        self.iter()
            .fold(hasher.leaf(item), |curr, (side, neighbor)| {
                let (l, r) = side.order(&curr, neighbor);
                hasher.intermediate(l, r)
            })
    }

    /// Verifies that this path matches a given merkle root.
    pub fn verify_root<M: MerkleItem>(&self, root: &Hash, item: &M, hasher: &Hasher<M>) -> bool {
        self.compute_root(item, hasher).ct_eq(&root).unwrap_u8() == 1
    }
}

impl Encodable for Path {
    fn encode(&self, w: &mut impl Writer) -> Result<(), WriteError> {
        w.write_u64(b"position", self.position)?;
        w.write_u32(b"n", self.neighbors.len() as u32)?;
        for hash in self.neighbors.iter() {
            w.write(b"hash", &hash[..])?;
        }
        Ok(())
    }
}

impl ExactSizeEncodable for Path {
    fn encoded_size(&self) -> usize {
        8 + 4 + 32 * self.neighbors.len()
    }
}

impl Decodable for Path {
    fn decode(reader: &mut impl Reader) -> Result<Self, ReadError> {
        let position = reader.read_u64()?;
        let n = reader.read_u32()? as usize;
        let neighbors = reader.read_vec(n, |r| r.read_u8x32().map(Hash))?;
        Ok(Path {
            position,
            neighbors,
        })
    }
}

/// Similar to `Path`, but does not contain neighbors - only left/right directions
/// as indicated by the bits in the `position`.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Directions {
    position: Position,
    depth: usize,
}

impl Directions {
    /// Creates a new directions object for a specified item’s position and depth.
    pub fn new(position: Position, depth: usize) -> Self {
        Self { position, depth }
    }
}

impl ExactSizeIterator for Directions {
    fn len(&self) -> usize {
        self.depth
    }
}

impl Iterator for Directions {
    type Item = Side;
    fn next(&mut self) -> Option<Self::Item> {
        if self.depth == 0 {
            return None;
        }
        let side = Side::from_bit((self.position & 1) as u8);
        // kick out the lowest bit and shrink the depth
        self.position >>= 1;
        self.depth -= 1;
        Some(side)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

impl DoubleEndedIterator for Directions {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.depth == 0 {
            return None;
        }
        self.depth -= 1;
        // Note: we do not mask out the bit in `position` because we don't expose it.
        // The bit is ignored implicitly by having the depth decremented.
        let side = Side::from_bit(((self.position >> self.depth) & 1) as u8);
        Some(side)
    }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct BytesVisitor;

        impl<'de> serde::de::Visitor<'de> for BytesVisitor {
            type Value = Hash;

            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                formatter.write_str("a valid 32-byte string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Hash, E>
            where
                E: serde::de::Error,
            {
                if v.len() == 32 {
                    let mut buf = [0u8; 32];
                    buf[0..32].copy_from_slice(v);
                    Ok(Hash(buf))
                } else {
                    Err(serde::de::Error::invalid_length(v.len(), &self))
                }
            }
        }

        deserializer.deserialize_bytes(BytesVisitor)
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
            let hasher = Hasher::new(b"test");
            let (item, root, path) = {
                let items = test_items(*$num as usize);
                let path = Path::new(&items, *$idx as usize, &hasher).unwrap();
                let root = path.compute_root(&items[*$idx], &hasher);
                (items[*$idx as usize].clone(), root, path)
            };
            assert!(path.verify_root(&root, &item, &hasher));
        };
    }

    macro_rules! assert_proof_err {
        ($num:ident, $idx:ident, $wrong_idx:ident) => {
            let hasher = Hasher::new(b"test");
            let (item, root, path) = {
                let items = test_items(*$num as usize);
                let path = Path::new(&items, *$idx as usize, &hasher).unwrap();
                let root = path.compute_root(&items[*$idx], &hasher);
                (items[*$wrong_idx as usize].clone(), root, path)
            };
            assert!(path.verify_root(&root, &item, &hasher) == false);
        };
    }

    #[test]
    fn invalid_range() {
        let entries = test_items(5);
        assert!(Path::new(&entries, 7, &Hasher::new(b"test")).is_none());
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
