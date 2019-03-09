use merlin::Transcript;
use std::cmp::min;
use subtle::ConstantTimeEq;

use crate::errors::VMError;

pub struct PatriciaTree {
    root: Node,
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
    key: &'static [u8],
    bitmask: u8,
}

impl PatriciaTree {
    pub fn new() -> Self {
        PatriciaTree {
            root: Node{
                item: None,
                children: None,
            }
        }
    }

    pub fn insert(self, item: &'static [u8]) -> Result<Self, VMError> {
        Ok(Self{
            root: self.root.insert(item)?,
        })
    }

    pub fn remove(self, item: &'static [u8]) -> Result<Self, VMError> {
        let root = self.root.remove(item)?;
        match root {
            Some(r) => Ok(Self{ root: r}),
            None => Ok(Self::new())
        }
    }

    pub fn hash(&self) -> Result<[u8; 32], VMError> {
        self.root.hash()
    }

    fn print(&self) {
        self.root.print();
    }
}

impl Node {
    

    fn insert(self, insert: &'static [u8]) -> Result<Node, VMError> {
        // TBD: when to initialize transcript?
        let item = &self.item.clone();
        let is_child = self.children.is_some();
        match (item, is_child) {
            (None, false) => {
                // Empty node, insert the item at the root.
                return Ok(Node {
                    item: Some(PatriciaItem{
                        key: insert,
                        bitmask: 7,
                    }),
                    children: None,
                });
            },
            (Some(i), false) => {
                // Leaf node
                return self.insert_leaf(insert, i);
            },
            (Some(i), true) => {
                // Intermediary node
                return self.insert_intermediate(insert, i);
            },
            // TBD: better error
            (_, _) => Err(VMError::InvalidMerkleProof),
        }
    }

    fn insert_leaf(self, insert: &'static [u8], item: &PatriciaItem) -> Result<Node, VMError> {
        if item.key == insert {
            return Ok(self);
        }
        if item.is_prefix(insert) {
            return Err(VMError::InvalidMerkleProof);
        }

        let t = Transcript::new(b"patricia");

        // Find common split
        let (byte, bit) = item.last_matching_bit(insert);
        let matching_bytes = &item.key[..byte+1];

        // Construct new children
        let new_child = Node {
            item: Some(item.clone()),
            children: None,
        };
        let insert_child = Node{
            item: Some(PatriciaItem {
                key: insert,
                bitmask: 7,
            }),
            children: None,
        };

        // Add children to parent
        if bit_after(&item.key, byte, bit) == 0 {
            return Ok(Node{
                item: Some(PatriciaItem{
                    key: matching_bytes,
                    bitmask: bit,
                }),
                children: Some((Box::new(new_child), Box::new(insert_child))),
            });
        } else {
            return Ok(Node {
                item: Some(PatriciaItem{
                    key: matching_bytes,
                    bitmask: bit,
                }),
                children: Some((Box::new(insert_child), Box::new(new_child))),
            });
        }
    }

    fn insert_intermediate(mut self, insert: &'static [u8], item: &PatriciaItem) -> Result<Node, VMError> {
        if item.key == insert {
            return Ok(self);
        }
        let t = Transcript::new(b"patricia");

        if item.is_prefix(insert) {
            if let Some((l, r)) = self.children {
                if bit_after(insert, item.key.len() - 1, item.bitmask) == 0 {
                    let left = l.insert(insert)?;
                    return Ok(
                        Node {
                            item: Some(PatriciaItem{
                                key: item.key,
                                bitmask: item.bitmask,
                            }),
                            children: Some((Box::new(left), r)),
                        }
                    )
                } else {
                    let right = r.insert(insert)?;
                    return Ok(
                        Node {
                            item: Some(PatriciaItem{
                                key: item.key,
                                bitmask: item.bitmask,
                            }),
                            children: Some((l, Box::new(right))),
                        }
                    )
                }
            }
            return Err(VMError::InvalidMerkleProof);
        }

        // If not prefix, find common split
        let (byte, bit) = item.last_matching_bit(insert);
        let matching_bytes = &item.key[..byte + 1];

        let insert_child = Node{
            item: Some(PatriciaItem{
                key: insert,
                bitmask: 7,
            }),
            children: None,
        };

        if bit_after(&item.key, byte, bit) == 0 {
            return Ok(Node{
                item: Some(PatriciaItem{
                    key: matching_bytes,
                    bitmask: bit,
                }),
                children: Some((Box::new(self), Box::new(insert_child))),
            })
        } else {
            return Ok(Node{
                item: Some(PatriciaItem{
                    key: matching_bytes,
                    bitmask: bit,
                }),
                children: Some((Box::new(insert_child), Box::new(self))),
            })
        }
    }

    fn print(&self) {
        match (&self.item, &self.children) {
            (Some(i), Some((l, r))) => {
                l.print();
                r.print();
            }, (Some(i), None) => {
                println!("{:?}", i.key);
            },
            (_, _) => {
                return;
            }
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
        let idx = self.key.len();
        if self.key[..idx].ct_eq(&item[..idx]).unwrap_u8() != 1 {
            return false;
        }

        // Check equality of last byte of prefix with some bits masked
        let masked_prefix = self.key[idx - 1] >> self.bitmask << self.bitmask;
        let masked_item = item[idx - 1] >> self.bitmask << self.bitmask;
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
                            if i == 0 {
                                return (i, j);
                            }
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
        let byte = byte + 1;
        let bit = 0;
    } else {
        let bit = bit + 1;
    }
    return slice[byte-1] >> (7-bit) & 1;
}

fn bit(byte: u8, bitmask: u8) -> u8 {
    byte >> (7 - bitmask) & 1
}

fn mask(byte: u8, bitmask: u8) -> u8 {
    byte << (7 - bitmask) >> (7 - bitmask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic() {
        let tree = PatriciaTree::new();
        let tree = tree.insert(b"hello").unwrap();
        let tree = tree.insert(b"hellb").unwrap();
        let tree = tree.insert(b"helbo").unwrap();
        tree.print();

        let tree = tree.remove(b"hellb").unwrap();
        tree.print();
        assert!(false);
    }
}

/* scratch */

/*
fn remove(self, remove: &'static [u8]) -> Result<Option<Node>, VMError> {
        let item = &self.item.clone();
        let is_child = self.children.is_some();
        match (item, is_child) {
            (None, false) => {
                // Empty node, cannot remove
                return Err(VMError::InvalidMerkleProof);
            },
            (Some(i), false) => {
                // Leaf node
                if i.key == remove {
                    return Ok(None);
                }
                return Err(VMError::InvalidMerkleProof);
            },
            (Some(i), true) => {
                // Intermediary node
                if i.key == remove {
                    // All items should be located in leaf nodes
                    return Err(VMError::InvalidMerkleProof);
                }
                if i.is_prefix(remove) {
                    if let Some((l, r)) = self.children {
                        if bit_after(remove, i.key.len() - 1, i.bitmask) == 0 {
                            let l = l.remove(remove)?;
                            match l {
                                Some(l) => {
                                    let t = Transcript::new(b"patricia");
                                    return Ok(Some(Node{
                                        item: Some(PatriciaItem{
                                            key: i.key,
                                            hash: hash_node(&l.hash()?, &r.hash()?, t.clone()),
                                            bitmask: i.bitmask,
                                        }),
                                        children: Some((Box::new(l), r)),
                                    }))
                                }, None => {
                                    return Ok(Some(*r))
                                }
                            }
                        } else {
                            let r = r.remove(remove)?;
                            match r {
                                Some(r) => {
                                    let t = Transcript::new(b"patricia");
                                    return Ok(Some(Node{
                                        item: Some(PatriciaItem{
                                            key: i.key,
                                            hash: hash_node(&l.hash()?, &r.hash()?, t.clone()),
                                            bitmask: i.bitmask,
                                        }),
                                        children: Some((l, Box::new(r))),
                                    }))
                                }, None => {
                                    return Ok(Some(*l))
                                }
                            }
                        }
                    }
                } else {
                }
                return Err(VMError::InvalidMerkleProof);
            }, 
            (_, _) => return Err(VMError::InvalidMerkleProof),
        }
    }
*/
