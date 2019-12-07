use serde::{Deserialize, Serialize};

use super::super::encoding::{self, Encodable};
use crate::merkle::Hash;

/// Absolute position of an item in the tree.
pub type Position = u64;

/// Proof of inclusion in the Utreexo accumulator.
/// Transient items (those that were inserted before the forest is normalized)
/// do not have merkle paths and therefore come with a special `Proof::Transient`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Proof {
    /// Proof without a merkle path because the item was not committed to utreexo yet.
    Transient,
    /// Proof with a merkle path for an item that was stored in a normalized forest.
    Committed(Path),
}

/// Merkle proof of inclusion of a node in a `Forest`.
/// The exact tree is determined by the `position`, an absolute position of the item
/// within the set of all items in the forest.
/// Neighbors are counted from lowest to the highest.
/// Left/right position of the neighbor is determined by the appropriate bit in `position`.
/// (Lowest bit=1 means the first neighbor is to the left of the node.)
/// `path` is None if this proof is for a newly added item that has no merkle path yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Path {
    pub(super) position: Position,
    pub(super) neighbors: Vec<Hash>,
}

#[derive(Copy, Clone, PartialEq, Debug)]
pub(super) enum Side {
    Left,
    Right,
}

impl Proof {
    /// Returns a reference to a path if this proof contains one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Proof::Transient => None,
            Proof::Committed(p) => Some(p),
        }
    }
}

impl Side {
    /// Orders (current, neighbor) pair of nodes as (left, right)
    /// Alternative meaning in context of a path traversal: orders (left, right) pair of nodes as (main, neighbor)
    pub(super) fn order<T>(self, a: T, b: T) -> (T, T) {
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
    pub(super) fn iter(
        &self,
    ) -> impl DoubleEndedIterator<Item = (Side, &Hash)> + ExactSizeIterator {
        self.directions().zip(self.neighbors.iter())
    }
    fn directions(&self) -> Directions {
        Directions {
            position: self.position,
            depth: self.neighbors.len(),
        }
    }
}

impl Encodable for Proof {
    fn encode(&self, buf: &mut Vec<u8>) {
        match self {
            Proof::Transient => {
                encoding::write_u8(0, buf);
            }
            Proof::Committed(path) => {
                encoding::write_u8(1, buf);
                path.encode(buf);
            }
        }
    }

    fn serialized_length(&self) -> usize {
        match self {
            Proof::Transient => 1,
            Proof::Committed(path) => 1 + path.serialized_length(),
        }
    }
}

impl Encodable for Path {
    fn encode(&self, buf: &mut Vec<u8>) {
        encoding::write_u64(self.position, buf);
        encoding::write_size(self.neighbors.len(), buf);
        for hash in self.neighbors.iter() {
            encoding::write_bytes(&hash[..], buf);
        }
    }

    fn serialized_length(&self) -> usize {
        return 8 + 4 + 32 * self.neighbors.len();
    }
}

/// Simialr to Path, but does not contain neighbors - only left/right directions
/// as indicated by the bits in the `position`.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(super) struct Directions {
    pub(super) position: Position,
    pub(super) depth: usize,
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
