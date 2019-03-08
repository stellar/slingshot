use std::cmp::min;
use subtle::ConstantTimeEq;

use crate::errors::VMError;

pub struct PatriciaTree {
    root: PatriciaNode,
}

pub enum PatriciaNode {
    Empty(),
    Leaf(PatriciaItem),
    Node(PatriciaItem, Box<PatriciaNode>, Box<PatriciaNode>),
}

#[derive(Clone)]
struct PatriciaItem {
    key: &'static [u8],
    hash: [u8; 32],
    bitmask: u8,
}

impl PatriciaTree {
    pub fn new() -> Self {
        unimplemented!()
    }

    pub fn insert(&self, item: &[u8]) -> Result<(), VMError> {
        unimplemented!()
    }
}

impl PatriciaNode {
    fn insert(self, insert: &'static [u8]) -> Result<Self, VMError> {
        match self {
            PatriciaNode::Empty() => {
                return Ok(PatriciaNode::Leaf(PatriciaItem {
                    key: insert,
                    hash: hash(insert),
                    bitmask: 7,
                }));
            }
            PatriciaNode::Leaf(p) => {
                if p.key == insert {
                    return Ok(self);
                }
                return Ok(insert_helper(insert, p, None)?)
            }
            PatriciaNode::Node(item, l, r) => {
                if item.key == insert {
                    return Ok(self);
                }
                return Ok(insert_helper(insert, item, Some((l, r)))?)
            }
        }
    }
}

fn insert_helper(insert: &'static [u8], item: PatriciaItem, children: Option<(Box<PatriciaNode>, Box<PatriciaNode>)>) -> Result<PatriciaNode, VMError> {
    if item.is_prefix(insert) {
        return Err(VMError::InvalidMerkleProof);
    }

    // Find common split
    let (byte, bit) = item.last_matching_bit(insert);
    let matching_bytes = &item.key[..byte + 1];

    let parent = PatriciaItem {
        key: matching_bytes,
        hash: hash(matching_bytes),
        bitmask: bit,
    };

    // let item.bitmask = 7;
    let item = PatriciaItem {
        key: item.key,
        hash: item.hash,
        bitmask: 7,
    };
    let new_child = match children {
        Some((l, r)) => {
            PatriciaNode::Node(item, l, r)
        },
        None => PatriciaNode::Leaf(item),
    };

    let insert_child = PatriciaNode::Leaf(
        PatriciaItem {
            key: insert,
            hash: hash(&insert),
            bitmask: 7,
        }
    );

    if bit_after(&item.key, byte, bit) == 0 {
        return Ok(PatriciaNode::Node(
            parent,
            Box::new(new_child),
            Box::new(insert_child),
        ));
    } else {
        return Ok(PatriciaNode::Node(
            parent,
            Box::new(insert_child),
            Box::new(new_child),
        ));
    }
}

impl PatriciaItem {
    /// Returns true if the node's key is a prefix of the item.
    fn is_prefix(&self, item: &[u8]) -> bool {
        if self.key.len() == 0 {
            return true;
        }

        if self.key.len() > item.len() {
            return false;
        }

        // Check equality until last byte of prefix
        let idx = self.key.len() - 1;
        if self.key[..idx].ct_eq(&item[..idx]).unwrap_u8() != 1 {
            return false;
        }

        // Check equality of last byte of prefix with some bits masked
        let masked_prefix = self.key[idx] >> self.bitmask << self.bitmask;
        let masked_item = item[idx] >> self.bitmask << self.bitmask;
        return masked_prefix == masked_item;
    }

    /// Returns the pair of the byte and bit offset of the last matching bit
    /// between the two items
    fn last_matching_bit(&self, item: &[u8]) -> (usize, u8) {
        let key = self.key;
        for i in 0..min(key.len(), item.len()) {
            // Compare byte equality
            if key[i] != item[i] {
                // Get bit equality
                for j in 0..8 {
                    if mask(key[i], j) != mask(item[i], j) {
                        if j == 0 {
                            return (i - 1, 7);
                        }
                        return (i, j - 1);
                    }
                }
            }
        }
        return (min(key.len(), item.len()) - 1, 7);
    }
}

/// Returns the bit after the given (byte, bit) offset for
/// the input slice.
fn bit_after(slice: &[u8], byte: usize, bit: u8) -> u8 {
    if bit == 7 {
        byte = byte + 1;
        bit = 0;
    } else {
        bit = bit + 1;
    }
    return slice[byte] >> (7 - bit) & 1;
}

fn bit(byte: u8, bitmask: u8) -> u8 {
    byte >> (7 - bitmask) & 1
}

fn mask(byte: u8, bitmask: u8) -> u8 {
    byte << (7 - bitmask) >> (7 - bitmask)
}

fn hash(item: &[u8]) -> [u8; 32] {
    unimplemented!()
}
