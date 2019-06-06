use crate::merkle::MerkleItem;
use core::marker::PhantomData;
use core::mem;
use merlin::Transcript;
use std::collections::HashMap;

use super::bitarray::Bitarray;
use super::nodes::Hash;


#[derive(Clone)]
struct Insertions {
    list: Vec<Hash>,
    deletions: Bitarray,
}

impl Insertions {



    /// Finds an index of the hash in the list of freshly inserted items.
    fn find_insertion(&self, hash: &Hash) -> Option<usize> {
        self.list
            .iter()
            .enumerate()
            .find(|&(_i, ref h)| h == &hash)
            .map(|(i, _h)| i)
    }
}
