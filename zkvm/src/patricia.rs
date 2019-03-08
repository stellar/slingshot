use merlin::Transcript;
use subtle::ConstantTimeEq;

use crate::errors::VMError;
// use crate::merkle::MerkleItem;

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

// pub struct PatriciaNode {
//     // TBD: do we want this to be &[u8] (doesn't necessarily make a lot of sense)
//     // or &'static [u8] ? 
//     key: Vec<u8>,
//     hash: [u8; 32],
//     // Number of bits to mask in comparisons
//     bitmask: u8,
//     leaf: bool,
//     children: (Option<Box<PatriciaNode>>, Box<PatriciaNode>),
// }

impl PatriciaTree {
    pub fn new() -> Self {
        unimplemented!()
    }

    pub fn insert(&self, item: &[u8]) -> Result<(), VMError> {
        unimplemented!()
        // self.root.insert(item)?
    }
}

impl PatriciaNode {
    fn insert(&self, item: &[u8]) -> Result<&Self, VMError> {
        match self {
            PatriciaNode::Empty() => {
                return Ok(&PatriciaNode::Leaf(PatriciaItem{
                    key: item.to_vec(),
                    hash: hash(item),
                    bitmask: 7,
                }));
            },
            PatriciaNode::Leaf(p) => {
                if p.key == item {
                    return Ok(self)
                }
                if p.is_prefix(item) {
                    return Err(VMError::InvalidMerkleProof)
                }
                // if not prefix, tbd
            },
            PatriciaNode::Node(item, l, r) => {
                unimplemented!()
            }
        };

        if self.key == item {
            if self.leaf {
                return Ok(());
            }
            // Attempting to insert a prefix
            return Err(VMError::InvalidMerkleProof);
        }

        if self.is_prefix(item) {
            if self.leaf {
                // Attempting to insert a prefix
                return Err(VMError::InvalidMerkleProof);
            }

            let bit = 0;
            // TODO: figure out how to choose the branching bit 
            if bit == 0 {
                self.children.0.insert(item)?;
            }
            
        }

        unimplemented!()
    }
}

impl PatriciaItem {

    /// Returns true if the node's key is a prefix of the item.
    fn is_prefix(&self, item: &[u8]) -> bool {
        if self.key.len() == 0 {
            return true
        }

        if self.key.len() > item.len() {
            return false
        }

        // Check equality until last byte of prefix
        let idx = self.key.len()-1;
        if self.key[..idx].ct_eq(&item[..idx]).unwrap_u8() != 1 {
            return false
        }

        // Check equality of last byte of prefix with some bits masked
        let masked_prefix = self.key[idx] >> self.bitmask << self.bitmask;
        let masked_item = item[idx] >> self.bitmask << self.bitmask;
        return masked_prefix == masked_item
    }
}

pub fn hash(item: &[u8]) -> [u8; 32] {
    unimplemented!()
}
