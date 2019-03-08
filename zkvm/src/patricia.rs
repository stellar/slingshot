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

struct PatriciaItem {
    key: Vec<u8>,
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
    fn insert(&self, item: &[u8]) -> Result<&Self, VMError> {
        match self {
            PatriciaNode::Empty() => {
                return Ok(&PatriciaNode::Leaf(PatriciaItem {
                    key: item.to_vec(),
                    hash: hash(item),
                    bitmask: 7,
                }));
            }
            PatriciaNode::Leaf(p) => {
                if p.key == item {
                    return Ok(self);
                }
                if p.is_prefix(item) {
                    return Err(VMError::InvalidMerkleProof);
                }

                // Find common split
                let (byte, bit) = p.last_matching_bit(item);
                let matching_bytes = &p.key[..byte + 1];

                let parent_item = PatriciaItem {
                    key: matching_bytes.to_vec(),
                    hash: hash(matching_bytes),
                    bitmask: bit,
                };

                // TODO: move the leftover bits from the parent into
                // the new child accordingly - right now, this is wrong!
                let new_child = PatriciaItem {
                    key: p.key[byte + 1..].to_vec(),
                    hash: hash(&p.key[byte + 1..]),
                    bitmask: bit,
                };

                let insert_child = PatriciaItem {
                    key: item[byte + 1..].to_vec(),
                    hash: hash(&item[byte + 1..]),
                    bitmask: 7,
                };

                // Build two children
                if bit_after(&p.key, byte, bit) == 0 {
                    return Ok(&PatriciaNode::Node(
                        parent_item,
                        Box::new(PatriciaNode::Leaf(new_child)),
                        Box::new(PatriciaNode::Leaf(insert_child)),
                    ));
                } else {
                    return Ok(&PatriciaNode::Node(
                        parent_item,
                        Box::new(PatriciaNode::Leaf(insert_child)),
                        Box::new(PatriciaNode::Leaf(new_child)),
                    ));
                }
            }
            PatriciaNode::Node(item, l, r) => unimplemented!(),
        }
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
