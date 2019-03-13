use merlin::Transcript;
use std::cmp::min;
use subtle::ConstantTimeEq;

use crate::errors::VMError;

pub struct PatriciaTree {
    root: Node,
    size: usize,
}

struct Node {
    item: Option<PatriciaItem>,
    children: Option<(Box<Node>, Box<Node>)>,
}

enum PatriciaNode {
    Empty(),
    Leaf(PatriciaItem),
    Node(PatriciaItem, Box<PatriciaNode>, Box<PatriciaNode>),
}

#[derive(Clone)]
struct PatriciaItem {
    // TBD: should we use BitVec instead?
    key: &'static [u8],
    // position of the last bit to include in the key
    // ex: if we include the whole key [u8] slice, the
    // offset would be 7.
    bits: u8,
}

impl PatriciaTree {
    pub fn new() -> Self {
        PatriciaTree {
            root: Node {
                item: None,
                children: Some((Box::new(Node::empty()), Box::new(Node::empty()))),
            },
            size: 0,
        }
    }

    pub fn insert(self, item: &'static [u8]) -> Result<Self, VMError> {
        Ok(Self {
            root: self.root.insert(item)?,
            size: self.size + 1,
        })
    }

    pub fn remove(self, item: &'static [u8]) -> Result<Self, VMError> {
        Ok(Self {
            root: self.root.remove(item)?.ok_or(VMError::InvalidMerkleProof)?,
            size: self.size - 1,
        })
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
            children: None,
        }
    }

    fn insert(self, insert: &'static [u8]) -> Result<Node, VMError> {
        let item = &self.item.clone();
        let is_child = self.children.is_some();
        match (item, is_child) {
            // Inserting into empty
            (None, false) => {
                return Ok(Node {
                    item: Some(PatriciaItem {
                        key: insert,
                        bits: 7,
                    }),
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
                            children: Some((Box::new(l), r)),
                        });
                    } else {
                        let r = r.insert(insert)?;
                        return Ok(Node {
                            item: None,
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
            children: None,
        };
        let insert_child = Node {
            item: Some(PatriciaItem {
                key: insert,
                bits: 7,
            }),
            children: None,
        };

        // Add children to parent
        if bit_after(&item.key, byte, bit) == 0 {
            return Ok(Node {
                item: Some(PatriciaItem {
                    key: matching_bytes,
                    bits: bit,
                }),
                children: Some((Box::new(new_child), Box::new(insert_child))),
            });
        } else {
            return Ok(Node {
                item: Some(PatriciaItem {
                    key: matching_bytes,
                    bits: bit,
                }),
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
                        children: Some((Box::new(left), r)),
                    });
                } else {
                    let right = r.insert(insert)?;
                    return Ok(Node {
                        item: Some(PatriciaItem {
                            key: item.key.clone(),
                            bits: item.bits,
                        }),
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

        let insert_child = Node {
            item: Some(PatriciaItem {
                key: insert,
                bits: 7,
            }),
            children: None,
        };

        if bit_after(&item.key, byte, bit) == 0 {
            return Ok(Node {
                item: Some(PatriciaItem {
                    key: matching_bytes,
                    bits: bit,
                }),
                children: Some((Box::new(self), Box::new(insert_child))),
            });
        } else {
            return Ok(Node {
                item: Some(PatriciaItem {
                    key: matching_bytes,
                    bits: bit,
                }),
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
                                    children: Some((Box::new(l), r)),
                                }));
                            }
                            None => {
                                return Ok(Some(Node {
                                    item: None,
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
                                    children: Some((l, Box::new(r))),
                                }));
                            }
                            None => {
                                return Ok(Some(Node {
                                    item: None,
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

    fn print(&self) {
        match (&self.item, &self.children) {
            (_, Some((l, r))) => {
                l.print();
                r.print();
            }
            (Some(i), None) => {
                println!("{:?}", i.key);
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
fn bit_after(slice: &[u8], byte: usize, bit: u8) -> u8 {
    if bit == 7 {
        let byte = byte + 1;
        let bit = 0;
    } else {
        let bit = bit + 1;
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

        assert!(tree.insert(&[0b1111, 0b1111]).is_ok());
    }
}
