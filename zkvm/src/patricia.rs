use merlin::Transcript;
use std::cmp::min;
use subtle::ConstantTimeEq;

use crate::errors::VMError;

/// TBD: do we want to specify a length for
/// items in the tree?
pub struct PatriciaTree {
    root: Node,
    size: usize,
}

/// Doc
pub enum PatriciaNeighbor {
    /// Left
    Left([u8; 32]),
    /// Right
    Right([u8; 32]),
}

struct Node {
    /// Data held by this node
    item: Option<PatriciaItem>,
    /// Hash of the data in this node (if a leaf),
    /// or of the children concatenated
    hash: [u8; 32],
    /// Left (bit 0) and right (bit 1) nodes
    children: Option<(Box<Node>, Box<Node>)>,
}

enum PatriciaNode {
    Empty(),
    Leaf(PatriciaItem),
    Node(PatriciaItem, Box<PatriciaNode>, Box<PatriciaNode>),
}

#[derive(Clone)]
struct PatriciaItem {
    /// Key contained at this item: with the appropriate
    /// bits included, represents the data represented
    /// by this path of the Patricia tree.
    key: &'static [u8],
    /// Position of the last bit to include in the key
    /// ex: if we include the whole key [u8] slice, the
    //. offset would be 7.
    bits: u8,
}

impl PatriciaTree {
    /// new
    pub fn new() -> Self {
        PatriciaTree {
            root: Node {
                item: None,
                hash: [0u8; 32],
                children: Some((Box::new(Node::empty()), Box::new(Node::empty()))),
            },
            size: 0,
        }
    }

    /// insert
    pub fn insert(self, item: &'static [u8]) -> Result<Self, VMError> {
        Ok(Self {
            root: self.root.insert(item)?,
            size: self.size + 1,
        })
    }

    /// remove
    pub fn remove(self, item: &'static [u8]) -> Result<Self, VMError> {
        Ok(Self {
            root: self.root.remove(item)?.ok_or(VMError::InvalidMerkleProof)?,
            size: self.size - 1,
        })
    }

    /// root
    pub fn root(&self) -> [u8; 32] {
        self.root.hash
    }

    /// build_path
    pub fn build_path(&self, item: &'static[u8]) -> Result<Vec<PatriciaNeighbor>, VMError> {
        let mut path = Vec::new();
        self.root.build_path(item, &mut path)?;
        Ok(path)
    }

    fn print(&self) {
        self.root.print();
    }

    fn len(&self) -> usize {
        self.size
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

    fn insert(self, insert: &'static [u8]) -> Result<Node, VMError> {
        let item = &self.item.clone();
        let is_child = self.children.is_some();
        match (item, is_child) {
            // Inserting into empty
            (None, false) => {
                let insert_item = PatriciaItem {
                    key: insert,
                    bits: 7,
                };
                return Ok(Node {
                    hash: hash_leaf(&insert_item),
                    item: Some(insert_item),
                    children: None,
                });
            }
            // Leaf node
            (Some(i), false) => {
                return self.insert_leaf(insert, i);
            }
            // Intermediary node
            (Some(i), true) => {
                return self.insert_intermediate(insert, i);
            }
            // Root node
            (None, true) => match self.children {
                Some((l, r)) => {
                    if bit_at(insert[0], 0) == 0 {
                        let l = l.insert(insert)?;
                        return Ok(Node {
                            item: None,
                            hash: hash_node(&l, &r),
                            children: Some((Box::new(l), r)),
                        });
                    } else {
                        let r = r.insert(insert)?;
                        return Ok(Node {
                            item: None,
                            hash: hash_node(&l, &r),
                            children: Some((l, Box::new(r))),
                        });
                    }
                }
                None => Err(VMError::InvalidMerkleProof),
            },
        }
    }

    fn insert_leaf(self, insert: &'static [u8], item: &PatriciaItem) -> Result<Node, VMError> {
        if item.equals(insert) {
            return Ok(self);
        }
        if item.is_prefix(&insert) {
            return Err(VMError::InvalidMerkleProof);
        }

        // Find common split
        let (byte, bit) = item
            .last_matching_bit(&insert)
            .ok_or(VMError::FormatError)?;
        let matching_bytes = &item.key[..byte + 1];

        // Construct new children
        let new_child = Node {
            item: Some(item.clone()),
            hash: hash_leaf(item),
            children: None,
        };
        let insert_item = PatriciaItem {
            key: insert,
            bits: 7,
        };
        let insert_child = Node {
            hash: hash_leaf(&insert_item),
            item: Some(insert_item),
            children: None,
        };

        // Add children to parent
        if bit_after(&item.key, byte, bit) == 0 {
            return Ok(Node {
                item: Some(PatriciaItem {
                    key: matching_bytes,
                    bits: bit,
                }),
                hash: hash_node(&new_child, &insert_child),
                children: Some((Box::new(new_child), Box::new(insert_child))),
            });
        } else {
            return Ok(Node {
                item: Some(PatriciaItem {
                    key: matching_bytes,
                    bits: bit,
                }),
                hash: hash_node(&insert_child, &new_child),
                children: Some((Box::new(insert_child), Box::new(new_child))),
            });
        }
    }

    fn insert_intermediate(
        mut self,
        insert: &'static [u8],
        item: &PatriciaItem,
    ) -> Result<Node, VMError> {
        if item.equals(insert) {
            return Ok(self);
        }
        if item.is_prefix(&insert) {
            if let Some((l, r)) = self.children {
                if item.key.len() == 0 {}
                if bit_after(&insert, item.key.len() - 1, item.bits) == 0 {
                    let left = l.insert(insert)?;
                    return Ok(Node {
                        item: Some(PatriciaItem {
                            key: item.key.clone(),
                            bits: item.bits,
                        }),
                        hash: hash_node(&left, &r),
                        children: Some((Box::new(left), r)),
                    });
                } else {
                    let right = r.insert(insert)?;
                    return Ok(Node {
                        item: Some(PatriciaItem {
                            key: item.key.clone(),
                            bits: item.bits,
                        }),
                        hash: hash_node(&l, &right),
                        children: Some((l, Box::new(right))),
                    });
                }
            }
            return Err(VMError::InvalidMerkleProof);
        }

        // If not prefix, find common split
        let (byte, bit) = item
            .last_matching_bit(&insert)
            .ok_or(VMError::FormatError)?;
        let matching_bytes = &item.key[..byte + 1];

        let insert_item = PatriciaItem {
            key: insert,
            bits: 7,
        };
        let insert_child = Node {
            hash: hash_leaf(&insert_item),
            item: Some(insert_item),
            children: None,
        };

        if bit_after(&item.key, byte, bit) == 0 {
            return Ok(Node {
                item: Some(PatriciaItem {
                    key: matching_bytes,
                    bits: bit,
                }),
                hash: hash_node(&self, &insert_child),
                children: Some((Box::new(self), Box::new(insert_child))),
            });
        } else {
            return Ok(Node {
                item: Some(PatriciaItem {
                    key: matching_bytes,
                    bits: bit,
                }),
                hash: hash_node(&insert_child, &self),
                children: Some((Box::new(insert_child), Box::new(self))),
            });
        }
    }

    fn remove(self, remove: &'static [u8]) -> Result<Option<Node>, VMError> {
        let item = &self.item.clone();
        let is_child = self.children.is_some();
        match (item, is_child) {
            (None, false) => {
                // Empty node, cannot remove
                return Err(VMError::InvalidMerkleProof);
            }
            (Some(i), false) => {
                // Leaf node
                if i.equals(remove) {
                    return Ok(None);
                }
                return Err(VMError::InvalidMerkleProof);
            }
            (Some(i), true) => {
                // Intermediary node
                if i.equals(remove) {
                    // All items should be located in leaf nodes
                    return Err(VMError::InvalidMerkleProof);
                }
                if i.is_prefix(&remove) {
                    if let Some((l, r)) = self.children {
                        if bit_after(&remove, i.key.len() - 1, i.bits) == 0 {
                            let l = l.remove(remove)?;
                            match l {
                                Some(l) => {
                                    let t = Transcript::new(b"patricia");
                                    return Ok(Some(Node {
                                        item: Some(PatriciaItem {
                                            key: i.key.clone(),
                                            bits: i.bits,
                                        }),
                                        hash: hash_node(&l, &r),
                                        children: Some((Box::new(l), r)),
                                    }));
                                }
                                None => return Ok(Some(*r)),
                            }
                        } else {
                            let r = r.remove(remove)?;
                            match r {
                                Some(r) => {
                                    return Ok(Some(Node {
                                        item: Some(PatriciaItem {
                                            key: i.key.clone(),
                                            bits: i.bits,
                                        }),
                                        hash: hash_node(&l, &r),
                                        children: Some((l, Box::new(r))),
                                    }));
                                }
                                None => return Ok(Some(*l)),
                            }
                        }
                    }
                }
                return Err(VMError::InvalidMerkleProof);
            }
            (None, true) => match self.children {
                Some((l, r)) => {
                    if bit_at(remove[0], 0) == 0 {
                        let l = l.remove(remove)?;
                        match l {
                            Some(l) => {
                                return Ok(Some(Node {
                                    item: None,
                                    hash: hash_node(&l, &r),
                                    children: Some((Box::new(l), r)),
                                }));
                            }
                            None => {
                                return Ok(Some(Node {
                                    item: None,
                                    hash: hash_node(&Node::empty(), &r),
                                    children: Some((Box::new(Node::empty()), r)),
                                }));
                            }
                        }
                    } else {
                        let r = r.remove(remove)?;
                        match r {
                            Some(r) => {
                                return Ok(Some(Node {
                                    item: None,
                                    hash: hash_node(&l, &r),
                                    children: Some((l, Box::new(r))),
                                }));
                            }
                            None => {
                                return Ok(Some(Node {
                                    item: None,
                                    hash: hash_node(&l, &Node::empty()),
                                    children: Some((l, Box::new(Node::empty()))),
                                }));
                            }
                        }
                    }
                }
                None => Err(VMError::InvalidMerkleProof),
            },
        }
    }

    fn build_path(&self, item: &'static [u8], result: &mut Vec<PatriciaNeighbor>) -> Result<(), VMError> {
        match (&self.item, &self.children) { 
            (Some(i), Some((l, r))) => {
                if i.is_prefix(item) {
                    if bit_after(item, i.key.len()-1, i.bits) == 0 {
                        result.insert(0, PatriciaNeighbor::Right(r.hash));
                        return l.build_path(item, result);
                    } else {
                        result.insert(0, PatriciaNeighbor::Left(l.hash));
                        return r.build_path(item, result);
                    }
                } else {
                    return Err(VMError::InvalidMerkleProof);
                }
            },
            (Some(i), None) => {
                if i.key == item {
                    return Ok(());
                } else {
                    // not found
                    return Err(VMError::InvalidMerkleProof);
                }
            },
            (None, Some((l, r))) => {
                if bit_at(item[0], 0) == 0 {
                    result.insert(0, PatriciaNeighbor::Right(r.hash));
                    return l.build_path(item, result);
                } else {
                    result.insert(0, PatriciaNeighbor::Right(l.hash));
                    return r.build_path(item, result);
                }
            },
            (None, None) => {
                // not found
                return Err(VMError::InvalidMerkleProof);
            }
        }
    }

    fn verify_path(item: &'static [u8], proof: Vec<PatriciaNeighbor>, root: &[u8; 32]) -> Result<(), VMError> {
        let insert_item = PatriciaItem{
            key: item,
            bits: 7,
        };
        let mut result = hash_leaf(&insert_item);
        for node in proof.iter() {
            let mut t = Transcript::new(b"ZkVM.patricia");
            match node {
                PatriciaNeighbor::Left(l) => {
                    t.commit_bytes(b"L", l);
                    t.commit_bytes(b"R", &result);
                    t.challenge_bytes(b"patricia.node", &mut result);
                },
                PatriciaNeighbor::Right(r) => {
                    t.commit_bytes(b"L", &result);
                    t.commit_bytes(b"R", r);
                    t.challenge_bytes(b"patricia.node", &mut result);
                }
            }
        }
        println!("Result: {:?}", result);
        if *root == result {
            return Ok(());
        }
        return Err(VMError::InvalidMerkleProof);
    }

    fn print(&self) {
        match (&self.item, &self.children) {
            (Some(i), Some((l, r))) => {
                println!("Item: {:?}, {:?}", i.key, i.bits);
                println!("Left...");
                l.print();
                println!("Right...");
                r.print();
            }
            (Some(i), None) => {
                println!("{:?}", i.key);
            }
            (None, Some((l, r))) => {
                println!("root.Left: ");
                l.print();
                println!("root.Right: ");
                r.print();
            }
            (_, _) => {
                return;
            }
        }
    }
}

impl PatriciaItem {
    fn equals(&self, item: &[u8]) -> bool {
        equals(&self.key, self.bits, item)
    }

    /// Returns true if the node's key is a prefix of the item.
    fn is_prefix(&self, item: &[u8]) -> bool {
        is_prefix(&self.key, self.bits, item)
    }

    /// Returns the pair of the byte and bit offset of the last matching bit
    /// between the two items
    fn last_matching_bit(&self, item: &[u8]) -> Option<(usize, u8)> {
        last_matching_bit(&self.key, item)
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

fn hash_leaf(item: &PatriciaItem) -> [u8; 32] {
    let mut t = Transcript::new(b"ZkVM.patricia");
    t.commit_bytes(b"item", item.key);
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

    let l_masked = l[idx - 1] << (7 - l_bits) >> (7 - l_bits);
    return l_masked == r[idx - 1];
}

fn is_prefix(prefix: &[u8], prefix_bits: u8, item: &[u8]) -> bool {
    if prefix.len() == 0 {
        return true;
    }

    if prefix.len() > item.len() {
        return false;
    }

    // // Check equality until last byte of prefix
    let idx = prefix.len();
    if prefix[..idx - 1] != item[..idx - 1] {
        return false;
    }

    // Check equality of last byte of prefix with some bits masked
    let masked_prefix = prefix[idx - 1] << (7 - prefix_bits) >> (7 - prefix_bits);
    let masked_item = item[idx - 1] << (7 - prefix_bits) >> (7 - prefix_bits);
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

fn bit_at(byte: u8, pos: u8) -> u8 {
    (byte >> pos) & 0x01
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_last_matching_bit() {
        let (byte, bit) = last_matching_bit(&[0b1000], &[0b1100]).unwrap();
        assert_eq!((byte, bit), (0, 1));

        let (byte, bit) =
            last_matching_bit(&[0b1111, 0b0100, 0b11101100], &[0b1111, 0b0100, 0b11101100])
                .unwrap();
        assert_eq!((byte, bit), (2, 7));

        let (byte, bit) =
            last_matching_bit(&[0b1111, 0b0100, 0b11101100], &[0b1111, 0b0100, 0b11111100])
                .unwrap();
        assert_eq!((byte, bit), (2, 3));
    }

    #[test]
    fn test_is_prefix() {
        assert!(is_prefix(&[0b01, 0b1000], 3, &[0b01, 0b11000]));
        assert_eq!(is_prefix(&[0b01, 0b1000], 4, &[0b01, 0b11000]), false);
    }

    #[test]
    fn test_insert() {
        let tree = PatriciaTree::new();
        let tree = tree.insert(&[0b0011]).unwrap();
        let tree = tree.insert(&[0b1111]).unwrap();
        let tree = tree.insert(&[0b0101]).unwrap();
        let tree = tree.insert(&[0b0110]).unwrap();
        let tree = tree.insert(&[0b1010]).unwrap();
        let tree = tree.insert(&[0b1011]).unwrap();
        assert_eq!(tree.len(), 6);

        let tree = tree.remove(&[0b0110]).unwrap();
        let tree = tree.remove(&[0b1010]).unwrap();
        assert_eq!(tree.len(), 4);

        assert!(tree.insert(&[0b1111]).is_ok());
    }

    #[test]
    fn test_proofs() {
        let tree = PatriciaTree::new();
        let find_item = &[0b0101];
        let tree = tree.insert(&[0b0011]).unwrap();
        let tree = tree.insert(&[0b1111]).unwrap();
        let tree = tree.insert(find_item).unwrap();
        let tree = tree.insert(&[0b0110]).unwrap();
        let tree = tree.insert(&[0b1010]).unwrap();
        let tree = tree.insert(&[0b1011]).unwrap();

        let root = tree.root();
        println!("Root: {:?}", root);
        let path = tree.build_path(find_item).unwrap();

        assert!(Node::verify_path(find_item, path, &root).is_ok());
    }
}
