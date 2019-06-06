use core::mem;
use super::bitarray::Bitarray;
use super::nodes::Hash;

#[derive(Clone,Default)]
pub(super) struct Insertions {
    list: Vec<Hash>,
    deletions: Bitarray,
}

impl Insertions {

    /// New insertions instance with a given capacity
    pub(super) fn with_capacity(cap: usize) -> Self {
        Self {
            list: Vec::with_capacity(cap),
            deletions: Bitarray::with_capacity(cap)
        }
    }

    /// Number of items in the collection, with deletions accounted for.
    pub(super) fn count(&self) -> usize {
        self.list.len() - self.deletions.count_ones()
    }

    /// Returns the amount of allocated memory
    pub(super) fn memory(&self) -> usize {
        self.list.capacity() * mem::size_of::<Hash>() + self.deletions.memory()
    }

    /// Checks that the item exists in the insertions list
    pub(super) fn verify(&self, hash: &Hash) -> bool {
        if let Some(_) = self.find_non_deleted(hash) {
            true
        } else {
            false
        }
    }

    /// Inserts a new item.
    pub(crate) fn insert(&mut self, hash: Hash) {
        self.list.push(hash);
    }

    /// Finds a non-deleted item and marks it as deleted.
    /// Returns `false` if the item is not found.
    pub(crate) fn delete(&mut self, hash: Hash) -> bool {
        if let Some(i) = self.find_non_deleted(&hash) {
            self.deletions.set_bit_at(i, true);
            true
        } else {
            false
        }
    }

    pub(super) fn update<F,T,E>(&mut self, closure: F) -> Result<T,E>
    where F: FnOnce(&mut Self) -> Result<T,E> {

        let prev_len = self.list.len();

        match closure(self) {
            Ok(r) => {
                // apply deletions and clear the deletion bits
                let mut adjustment = 0usize;
                for (i, did_remove) in self.deletions.iter().enumerate() {
                    if did_remove {
                        self.list.remove(i - adjustment);
                        adjustment+=1;
                    }
                }
                self.deletions.clear();
                Ok(r)
            },
            Err(e) => {
                // discard appended items, clear deletions bits, ignoring the deletions
                self.list.truncate(prev_len);
                self.deletions.clear();
                Err(e)
            }
        }
    }

    /// Finds an index of the hash in the list of freshly inserted items.
    /// Note: since the Utreexo tree by design allows inserting duplicate items
    /// (there is no way to prove non-membership except for enumerating all items in the accumulator),
    /// we need to preserve the same behavior for the insertions list.
    /// So if the item may have been inserted, then tagged as deleted, and inserted again,
    /// we need to be able to find its non-tagged location, ignoring all the tagged locations.
    fn find_non_deleted(&self, hash: &Hash) -> Option<usize> {
        self.list
            .iter()
            .enumerate()
            .find(|&(i, ref h)| h == &hash && !self.deletions.bit_at(i) )
            .map(|(i, _h)| i)
    }
}
