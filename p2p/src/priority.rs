//! Prioritization utilities.

use std::cmp::Eq;
use std::collections::HashMap;
use std::default::Default;
use std::hash::Hash;
use std::mem;

/// Priority of the peer address. Lower integer - higher priority.
pub type Priority = u64;

/// Top priority value for known items.
pub const HIGH_PRIORITY: u64 = 0;

/// Low priority for unknown items.
pub const LOW_PRIORITY: u64 = 1_000_000;

/// Fixed-size hashmap with eviction of the lowest-priority items.
#[derive(Debug)]
pub struct PriorityTable<K: Hash + Eq> {
    capacity: usize,
    items: HashMap<K, Priority>,
    batch_level: usize,
}

impl<K: Hash + Eq> PriorityTable<K> {
    /// Creates a new priority table with the given size limit.
    /// Lowest-priority items will be evicted when capacity is exceeded.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            items: Default::default(),
            batch_level: 0,
        }
    }

    /// Inserts or updates an item with a better priority.
    /// Returns true if the item already existed and had lower priority.
    pub fn insert(&mut self, item: K, new_priority: Priority) -> bool {
        // If the item already exists, bump its priority.
        if let Some(curr_priority) = self.items.get_mut(&item) {
            if new_priority < *curr_priority {
                *curr_priority = new_priority;
                return true;
            }
        } else {
            self.items.insert(item, new_priority);
            self.resize_if_needed();
        }
        return false;
    }

    pub fn remove(&mut self, item: &K) -> Option<Priority> {
        self.items.remove(item)
    }

    pub fn get(&self, item: &K) -> Option<Priority> {
        self.items.get(item).map(|p| *p)
    }

    /// Perform multiple insertions as a group w/o expensive reordering per each insertion.
    pub fn batch(&mut self, f: impl FnOnce(&mut Self)) {
        self.batch_level += 1;
        f(self);
        self.batch_level -= 1;
        self.resize_if_needed();
    }

    /// Actual number of items. Can be greater than capacity() within batch().
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Iterates the items in the priority order.
    pub fn iter(&self) -> impl Iterator<Item = &K> {
        let mut list = self.items.iter().collect::<Vec<_>>();
        list.sort_by_key(|&(_, priority)| priority);
        list.into_iter().map(|(k, _p)| k)
    }

    /// Very simple sorting algorithm.
    /// Ideally we'd be storing a hashmap of borrowed keys and
    /// doing log(n) insertion keeping the list always sorted.
    /// But for now this is not performance-critical.
    fn resize_if_needed(&mut self) {
        if self.batch_level > 0 {
            return;
        }
        if self.items.len() < self.capacity {
            return;
        }

        let hashmap = mem::replace(&mut self.items, Default::default());
        let mut list = hashmap.into_iter().collect::<Vec<_>>();
        list.sort_by_key(|&(_, priority)| priority);
        list.truncate(self.capacity);
        self.items.extend(list);
    }
}
