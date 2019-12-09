use serde::{Deserialize, Serialize};

/// Clone-on-write heap implementation with the following key features:
/// 1. No lifetimes - does not poison the APIs using it.
/// 2. Compatible with cross-thread access (if you access this via Mutex/RwLock)
///    because there are no smart pointers.
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Heap<T: Clone> {
    checkpoint: usize, // all items before this index are considered immutable and cloned by `make_mut`.
    items: Vec<T>,
}

#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct HeapIndex(usize);

pub struct HeapCheckpoint {
    prev: usize,
    curr: usize,
}

impl<T: Clone> Heap<T> {
    /// Creates a new empty heap.
    pub fn new() -> Self {
        Self {
            checkpoint: 0,
            items: Vec::new(),
        }
    }

    /// Creates a checkpoint: remembers which items must remain unchanged until a rollback.
    pub fn checkpoint(&mut self) -> HeapCheckpoint {
        let cp = HeapCheckpoint {
            prev: self.checkpoint,
            curr: self.items.len(),
        };
        self.checkpoint = cp.curr;
        cp
    }

    /// Rolls back to the previous state.
    /// Panics if the wrong checkpoint is used.
    pub fn rollback(&mut self, checkpoint: HeapCheckpoint) {
        assert!(self.checkpoint == checkpoint.curr);
        self.items.truncate(checkpoint.curr);
        self.checkpoint = checkpoint.prev;
    }

    /// Commits existing changes and shifts checkpoint to the previous position.
    pub fn commit(&mut self, checkpoint: HeapCheckpoint) {
        assert!(self.checkpoint == checkpoint.curr);
        self.checkpoint = checkpoint.prev;
    }

    /// Adds an item to the heap.
    pub fn allocate(&mut self, item: T) -> HeapIndex {
        self.items.push(item);
        HeapIndex(self.items.len() - 1)
    }

    /// Returns an immutable borrow of the item at index.
    pub fn get_ref(&self, index: HeapIndex) -> &T {
        &self.items[index.0]
    }

    /// Returns a mutable borrow of the item at index, or None if that
    /// item was created before the checkpoint
    pub fn get_mut(&mut self, index: HeapIndex) -> Option<&mut T> {
        if index.0 >= self.checkpoint {
            Some(&mut self.items[index.0])
        } else {
            None
        }
    }

    /// Returns a mutable borrow of the item at index.
    /// If the item exists in the backing heap, it is automatically cloned and inserted in this heap.
    /// The index is automatically updated to the new item in this case.
    pub fn make_mut(&mut self, index: &mut HeapIndex) -> &mut T {
        if index.0 < self.checkpoint {
            let item = self.items[index.0].clone();
            self.items.push(item);
            *index = HeapIndex(self.items.len() - 1);
        }
        &mut self.items[index.0]
    }
}
