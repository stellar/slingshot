use serde::{Deserialize, Serialize};

use super::super::encoding::{self, Encodable};
use crate::merkle::Path;

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

impl Proof {
    /// Returns a reference to a path if this proof contains one.
    pub fn path(&self) -> Option<&Path> {
        match self {
            Proof::Transient => None,
            Proof::Committed(p) => Some(p),
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
