//! Implements Utreexo scheme: compact accumulator for UTXOs based on merkle trees.
//! Based on the original proposal by Tadge Dryja.
//!
//! Operations:
//! 1. Verify the inclusion of an item using its merkle proof.
//! 2. Insert a new item and get its proof.
//! 3. Delete an existing item.
//! 4. Normalize the accumulator, shrinking its size.
//! 5. Automatically catch up proofs created against the previous state of the accumulator.

use crate::merkle::MerkleItem;
use core::marker::PhantomData;
use core::mem;
use merlin::Transcript;
use std::collections::HashMap;





