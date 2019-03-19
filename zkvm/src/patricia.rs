use merlin::Transcript;
use std::cmp::min;

use crate::errors::VMError;

/// Patricia tree for constructing Merkle proofs of
/// inclusion.
pub struct PatriciaTree {
    root: Node,
    size: usize,
}

/// Specifies a neighbor in the proof of inclusion.
#[derive(Clone, Debug)]
pub enum PatriciaNeighbor {
    /// Hash of left subtree
    Left([u8; 32]),
    /// Hash of right subtree
    Right([u8; 32]),
}

struct Node {
    /// Data held by this node
    item: Option<Item>,
    /// Hash of the data in this node (if a leaf),
    /// or of the children concatenated
    hash: [u8; 32],
    /// Left (bit 0) and right (bit 1) nodes
    children: Option<(Box<Node>, Box<Node>)>,
}

#[derive(Clone)]
struct Item {
    /// Key contained at this item: with the appropriate
    /// bits included, represents the data represented
    /// by this path of the Patricia tree.
    key: [u8; 32],

    // Position of the last byte to include in the key.
    byte_pos: usize,

    /// Position of the last bit to include in the key, starting
    /// from the most-significant bit. An offset of 7 includes
    /// the whole bit
    bit_pos: u8,
}

impl PatriciaTree {
    /// Constructs a new, empty PatriciaTree.
    pub fn new() -> Self {
        PatriciaTree {
            root: Node::empty(),
            size: 0,
        }
    }

    /// Inserts an item into the tree.
    pub fn insert(self, item: [u8; 32]) -> Result<Self, VMError> {
        Ok(Self {
            root: self.root.insert(item)?,
            size: self.size + 1,
        })
    }

    /// Removes an item from the tree.
    pub fn remove(self, item: [u8; 32]) -> Result<Self, VMError> {
        let root = match self.root.remove(item)? {
            Some(r) => r,
            None => Node::empty(),
        };

        Ok(Self {
            root: root,
            size: self.size - 1,
        })
    }

    /// Returns the Merkle tree root hash.
    pub fn root(&self) -> [u8; 32] {
        self.root.hash
    }

    /// Returns a path of inclusion for the given item.
    pub fn build_path(&self, item: [u8; 32]) -> Result<Vec<PatriciaNeighbor>, VMError> {
        let mut path = Vec::new();
        self.root.build_path(item, &mut path)?;
        Ok(path)
    }

    /// Takes an item, path of inclusion, and Merkle root and verifies the
    /// path of inclusion.
    pub fn verify_path(
        item: [u8; 32],
        proof: Vec<PatriciaNeighbor>,
        root: &[u8; 32],
    ) -> Result<(), VMError> {
        let insert_item = Item::leaf(item);
        let mut result = hash_leaf(&insert_item);
        for node in proof.iter() {
            let mut t = Transcript::new(b"ZkVM.patricia");
            match node {
                PatriciaNeighbor::Left(l) => {
                    t.commit_bytes(b"L", l);
                    t.commit_bytes(b"R", &result);
                    t.challenge_bytes(b"patricia.node", &mut result);
                }
                PatriciaNeighbor::Right(r) => {
                    t.commit_bytes(b"L", &result);
                    t.commit_bytes(b"R", r);
                    t.challenge_bytes(b"patricia.node", &mut result);
                }
            }
        }
        if *root == result {
            return Ok(());
        }
        return Err(VMError::InvalidMerkleProof);
    }
}

impl Node {
    fn empty() -> Self {
        Self {
            item: None,
            hash: [0u8; 32],
            children: None,
        }
    }

    fn leaf(item: Item) -> Self {
        Self {
            hash: hash_leaf(&item),
            item: Some(item),
            children: None,
        }
    }

    fn insert(self, insert: [u8; 32]) -> Result<Node, VMError> {
        let is_child = self.children.is_some();
        if self.item.is_none() {
            return Ok(Node::leaf(Item::leaf(insert)));
        }
        let item = self.item.clone();
        match (item, is_child) {
            // Root or empty node
            (None, _) => {
                return Ok(Node::leaf(Item::leaf(insert)));
            }
            // Leaf node
            (Some(i), false) => {
                return self.insert_leaf(insert, &i);
            }
            // Intermediary node
            (Some(i), true) => {
                return self.insert_intermediate(insert, &i);
            }
        }
    }

    fn insert_leaf(self, insert: [u8; 32], item: &Item) -> Result<Node, VMError> {
        if item.equals(&insert) {
            return Ok(self);
        }
        if item.is_prefix(&insert) {
            return Err(VMError::PatriciaPrefixInserted);
        }

        // Find common split
        let (byte, bit) = item
            .last_matching_bit(&insert)
            .ok_or(VMError::NoMatchingBits)?;

        // Construct new children
        let new_child = Node::leaf(item.clone());
        let insert_item = Item::leaf(insert);
        let insert_child = Node::leaf(insert_item);

        // Add children to parent
        let parent_item = Item {
            key: item.key,
            byte_pos: byte,
            bit_pos: bit,
        };
        match bit_after(&item.key, byte, bit) {
            0 => {
                return Ok(Node {
                    item: Some(parent_item),
                    hash: hash_node(&new_child, &insert_child),
                    children: Some((Box::new(new_child), Box::new(insert_child))),
                });
            }
            _ => {
                return Ok(Node {
                    item: Some(parent_item),
                    hash: hash_node(&insert_child, &new_child),
                    children: Some((Box::new(insert_child), Box::new(new_child))),
                });
            }
        };
    }

    fn insert_intermediate(self, insert: [u8; 32], item: &Item) -> Result<Node, VMError> {
        if item.equals(&insert) {
            return Ok(self);
        }

        // If the prefix matches, recursively insert into children
        if item.is_prefix(&insert) {
            if let Some((l, r)) = self.children {
                match bit_after(&insert, item.byte_pos, item.bit_pos) {
                    0 => {
                        let left = l.insert(insert)?;
                        return Ok(Node {
                            item: Some(item.clone()),
                            hash: hash_node(&left, &r),
                            children: Some((Box::new(left), r)),
                        });
                    }
                    _ => {
                        let right = r.insert(insert)?;
                        return Ok(Node {
                            item: Some(item.clone()),
                            hash: hash_node(&l, &right),
                            children: Some((l, Box::new(right))),
                        });
                    }
                };
            }
            return Err(VMError::PatriciaNodeNotFound);
        }

        // If not prefix, find common split
        let (byte, bit) = item
            .last_matching_bit(&insert)
            .ok_or(VMError::NoMatchingBits)?;
        let matching_item = Item {
            key: item.key,
            byte_pos: byte,
            bit_pos: bit,
        };

        let insert_child = Node::leaf(Item::leaf(insert));
        if bit_after(&item.key, byte, bit) == 0 {
            return Ok(Node {
                item: Some(matching_item),
                hash: hash_node(&self, &insert_child),
                children: Some((Box::new(self), Box::new(insert_child))),
            });
        } else {
            return Ok(Node {
                item: Some(matching_item),
                hash: hash_node(&insert_child, &self),
                children: Some((Box::new(insert_child), Box::new(self))),
            });
        }
    }

    fn remove(self, remove: [u8; 32]) -> Result<Option<Node>, VMError> {
        let is_child = self.children.is_some();
        match (&self.item, is_child) {
            // Empty node, cannot remove
            (None, _) => {
                return Err(VMError::PatriciaNodeNotFound);
            }
            // Leaf node
            (Some(i), false) => {
                if i.equals(&remove) {
                    return Ok(None);
                }
                return Err(VMError::PatriciaNodeNotFound);
            }
            // Intermediary node
            (Some(i), true) => {
                if i.is_prefix(&remove) {
                    if let Some((l, r)) = self.children {
                        match bit_after(&remove, i.byte_pos, i.bit_pos) {
                            0 => {
                                let l = l.remove(remove)?;
                                match l {
                                    Some(l) => {
                                        return Ok(Some(Node {
                                            item: Some(i.clone()),
                                            hash: hash_node(&l, &r),
                                            children: Some((Box::new(l), r)),
                                        }));
                                    }
                                    None => return Ok(Some(*r)),
                                }
                            }
                            _ => {
                                let r = r.remove(remove)?;
                                match r {
                                    Some(r) => {
                                        return Ok(Some(Node {
                                            item: Some(i.clone()),
                                            hash: hash_node(&l, &r),
                                            children: Some((l, Box::new(r))),
                                        }));
                                    }
                                    None => return Ok(Some(*l)),
                                }
                            }
                        };
                    }
                }
                return Err(VMError::PatriciaNodeNotFound);
            }
        }
    }

    fn build_path(
        &self,
        item: [u8; 32],
        result: &mut Vec<PatriciaNeighbor>,
    ) -> Result<(), VMError> {
        match (&self.item, &self.children) {
            (Some(i), Some((l, r))) => {
                if i.is_prefix(&item) {
                    match bit_after(&item, i.byte_pos, i.bit_pos) {
                        0 => {
                            result.insert(0, PatriciaNeighbor::Right(r.hash));
                            return l.build_path(item, result);
                        }
                        _ => {
                            result.insert(0, PatriciaNeighbor::Left(l.hash));
                            return r.build_path(item, result);
                        }
                    }
                } else {
                    return Err(VMError::PatriciaNodeNotFound);
                }
            }
            (Some(i), None) => {
                if i.key == item {
                    return Ok(());
                } else {
                    return Err(VMError::PatriciaNodeNotFound);
                }
            }
            (None, _) => {
                return Err(VMError::PatriciaNodeNotFound);
            }
        }
    }
}

impl Item {
    fn equals(&self, item: &[u8]) -> bool {
        equals(&self.key[..self.byte_pos + 1], self.bit_pos, item)
    }

    /// Returns true if the node's key is a prefix of the item.
    fn is_prefix(&self, item: &[u8]) -> bool {
        is_prefix(&self.key[..self.byte_pos + 1], self.bit_pos, item)
    }

    /// Returns the pair of the byte and bit offset of the last matching bit
    /// between the two items
    fn last_matching_bit(&self, item: &[u8]) -> Option<(usize, u8)> {
        last_matching_bit(&self.key, item)
    }

    /// Returns an item with maximum byte and bit positions for
    /// inserting at the leaf.
    fn leaf(item: [u8; 32]) -> Self {
        Self {
            key: item,
            byte_pos: 31,
            bit_pos: 7,
        }
    }
}

fn hash_node(l: &Node, r: &Node) -> [u8; 32] {
    let mut t = Transcript::new(b"ZkVM.patricia");
    t.commit_bytes(b"L", &l.hash);
    t.commit_bytes(b"R", &r.hash);
    let mut buf = [0u8; 32];
    t.challenge_bytes(b"patricia.node", &mut buf);
    buf
}

fn hash_leaf(item: &Item) -> [u8; 32] {
    let mut t = Transcript::new(b"ZkVM.patricia");
    t.commit_bytes(b"item", &item.key);
    let mut buf = [0u8; 32];
    t.challenge_bytes(b"patricia.leaf", &mut buf);
    buf
}

fn equals(l: &[u8], l_bits: u8, r: &[u8]) -> bool {
    if l.len() != r.len() {
        return false;
    }

    let idx = l.len();
    if l[..idx - 1] != r[..idx - 1] {
        return false;
    }

    let l_masked = l[idx - 1] >> (7 - l_bits) << (7 - l_bits);
    return l_masked == r[idx - 1];
}

/// Checks that the input `prefix` is a prefix of `item`, checking inclusion
/// up to bit with index `prefix_bits` of the last byte in the `prefix`.
fn is_prefix(prefix: &[u8], prefix_bits: u8, item: &[u8]) -> bool {
    if prefix.len() == 0 {
        return true;
    }

    if prefix.len() > item.len() {
        return false;
    }

    // Check equality until last byte of prefix
    let idx = prefix.len();
    if prefix[..idx - 1] != item[..idx - 1] {
        return false;
    }

    // Check equality of last byte of prefix with some bits masked
    let masked_prefix = prefix[idx - 1] >> (7 - prefix_bits) << (7 - prefix_bits);
    let masked_item = item[idx - 1] >> (7 - prefix_bits) << (7 - prefix_bits);
    return masked_prefix == masked_item;
}

fn last_matching_bit(l: &[u8], r: &[u8]) -> Option<(usize, u8)> {
    for i in 0..min(l.len(), r.len()) {
        // Compare byte equality
        if l[i] != r[i] {
            // Get bit equality
            for j in 0..8 {
                let l_bit = bit_at(l[i], j);
                let r_bit = bit_at(r[i], j);
                if l_bit != r_bit {
                    if j == 0 && i == 0 {
                        return None;
                    }
                    if j == 0 {
                        return Some((i - 1, 7));
                    }
                    return Some((i, j - 1));
                }
            }
        }
    }
    return Some((min(l.len(), r.len()) - 1, 7));
}

/// Returns the bit after the given (byte, bit) offset for
/// the input slice.
fn bit_after(slice: &[u8], mut byte: usize, mut bit: u8) -> u8 {
    if bit == 7 {
        byte = byte + 1;
        bit = 0;
    } else {
        bit = bit + 1;
    }
    return bit_at(slice[byte], bit);
}

/// Returns the byte at the given position, where the position
/// numbering starts at the most-significant bit.
fn bit_at(byte: u8, pos: u8) -> u8 {
    byte & (0x01 << (7 - pos))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper function to generate 32-byte slices and set
    /// the last byte for tests.
    fn test_slice(last_byte: u8) -> [u8; 32] {
        let mut item = [0u8; 32];
        item[31] = last_byte;
        item
    }

    #[test]
    fn test_last_matching_bit() {
        let (byte, bit) = last_matching_bit(&[0b1000], &[0b1100]).unwrap();
        assert_eq!((byte, bit), (0, 4));

        let (byte, bit) =
            last_matching_bit(&[0b1111, 0b0100, 0b11101100], &[0b1111, 0b0100, 0b11101100])
                .unwrap();
        assert_eq!((byte, bit), (2, 7));

        let (byte, bit) =
            last_matching_bit(&[0b1111, 0b0100, 0b11101100], &[0b1111, 0b0100, 0b11111100])
                .unwrap();
        assert_eq!((byte, bit), (2, 2));
    }

    #[test]
    fn test_is_prefix() {
        assert!(is_prefix(&[0b01, 0b00001000], 4, &[0b01, 0b00001111]));
        assert!(is_prefix(&[0b01, 0b00001110], 7, &[0b01, 0b00001110]));
        assert!(is_prefix(&[0b01, 0b00001110], 6, &[0b01, 0b00001111]));
        assert_eq!(
            is_prefix(&[0b01, 0b00001000], 5, &[0b01, 0b00001111]),
            false
        );
    }

    #[test]
    fn test_insert() {
        let tree = PatriciaTree::new();
        let tree = tree.insert(test_slice(0b0011)).unwrap();
        let tree = tree.insert(test_slice(0b1111)).unwrap();
        let tree = tree.insert(test_slice(0b0101)).unwrap();
        let tree = tree.insert(test_slice(0b0110)).unwrap();
        let tree = tree.insert(test_slice(0b1010)).unwrap();
        let tree = tree.insert(test_slice(0b1011)).unwrap();
        assert_eq!(tree.size, 6);

        let tree = tree.remove(test_slice(0b0110)).unwrap();
        let tree = tree.remove(test_slice(0b1010)).unwrap();
        assert_eq!(tree.size, 4);

        assert!(tree.insert(test_slice(0b1111)).is_ok());
    }

    #[test]
    fn test_proofs() {
        let tree = PatriciaTree::new();
        let find_item = test_slice(0b0101);
        let tree = tree.insert(test_slice(0b0011)).unwrap();
        let tree = tree.insert(test_slice(0b1111)).unwrap();
        let tree = tree.insert(find_item).unwrap();
        let tree = tree.insert(test_slice(0b0110)).unwrap();
        let tree = tree.insert(test_slice(0b1010)).unwrap();
        let tree = tree.insert(test_slice(0b1011)).unwrap();

        let path = tree.build_path(find_item).unwrap();
        let root = tree.root();
        assert!(PatriciaTree::verify_path(find_item, path.clone(), &root).is_ok());
        assert!(PatriciaTree::verify_path(find_item, path[1..].to_vec(), &root).is_err());

        let tree = tree.remove(test_slice(0b0110)).unwrap();
        assert!(PatriciaTree::verify_path(find_item, path.clone(), &tree.root()).is_err());
    }
}
