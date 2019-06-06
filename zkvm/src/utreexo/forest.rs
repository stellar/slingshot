use crate::merkle::MerkleItem;
use core::marker::PhantomData;
use core::mem;
use std::collections::HashMap;

use super::bitarray::Bitarray;
use super::path::{Position,Proof,Path,Directions};
use super::nodes::{Hash,NodeHasher,NodeIndex,Node,Heap};

/// Forest contains some number of perfect merkle binary trees
/// and a list of newly added items.
#[derive(Clone)]
pub struct Forest<M: MerkleItem> {
    generation: u64,
    roots: [Option<NodeIndex>; 64], // roots of the trees for levels 0 to 63
    insertions: Vec<Hash>, // new items (TBD: maybe use a fancy order-preserving HashSet later)
    deletions: usize,
    heap: Heap,
    hasher: NodeHasher<M>,
    phantom: PhantomData<M>,
}

/// An interface to the forest that makes all insertions/deletions atomic:
/// all changes are rolled back if any deletion is invalid.
pub struct Update<'f, M: MerkleItem> {
    forest: &'f mut Forest<M>,
    deleted_insertions: Bitarray,
}

/// Structure that helps auto-updating the proofs created for a previous generation of a forest.
#[derive(Clone)]
pub struct Catchup<M: MerkleItem> {
    forest: Forest<M>,            // forest that stores the nodes
    map: HashMap<Hash, Position>, // node hash -> new position offset for this node
    phantom: PhantomData<M>,
}

/// Metrics of the Forest.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Metrics {
    /// Generation of the forest.
    pub generation: u64,
    /// Sum of capacities of all roots.
    pub capacity: usize,
    /// Number of deletions.
    pub deletions: usize,
    /// Number of insertions.
    pub insertions: usize,
    /// Lower-bound for amount of memory occupied in bytes.
    pub memory: usize,
}

/// Represents an error in proof creation, verification, or parsing.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum UtreexoError {
    /// This error occurs when we receive a proof that's outdated and cannot be auto-updated.
    #[fail(display = "Item proof is outdated and must be re-created against the new state")]
    OutdatedProof,

    /// This error occurs when the merkle proof is too short or too long, or does not lead to a node
    /// to which it should.
    #[fail(display = "Merkle proof is invalid")]
    InvalidProof,
}


impl<M: MerkleItem> Forest<M> {
    /// Creates a new empty Forest.
    pub fn new() -> Forest<M> {
        Forest {
            generation: 0,
            roots: [None; 64],
            insertions: Vec::new(),
            deletions: 0,
            heap: Heap::with_capacity(0),
            hasher: NodeHasher::new(),
            phantom: PhantomData,
        }
    }

    /// Returns metrics data for this Forest
    pub fn metrics(&self) -> Metrics {
        Metrics {
            generation: self.generation,
            capacity: self.capacity() as usize,
            deletions: self.deletions,
            insertions: self.insertions.len(),
            memory: mem::size_of::<Self>()
                + mem::size_of::<Hash>() * self.insertions.len()
                + mem::size_of::<Heap>()
                + self.heap.memory(),
        }
    }

    /// Verifies the item's proof of inclusion.
    pub fn verify(&self, item: &M, proof: &Proof) -> Result<(), UtreexoError> {
        if proof.generation != self.generation {
            return Err(UtreexoError::OutdatedProof);
        }

        // 0. Fast check: if the proof relates to a newly added item.
        let path = match &proof.path {
            Some(path) => path,
            None => {
                let hash = self.hasher.leaf(item);
                return self
                    .find_insertion(&hash)
                    .map(|_| ())
                    .ok_or(UtreexoError::InvalidProof);
            }
        };

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let top = self.root_containing_position(path.position)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != top.level {
            return Err(UtreexoError::InvalidProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        //    And also check the higher-level neighbors in the proof.
        let existing = self.existing_node_for_path(top, &path)?;

        // If the existing node is the leaf, and it's marked as deleted - reject the proof
        if existing.level == 0 && existing.modified {
            return Err(UtreexoError::InvalidProof);
        }

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the bottom node.
        let current_hash = self.hasher.leaf(item);
        let current_hash = path
            .walk_up(current_hash, &self.hasher)
            .take(existing.level)
            .fold(current_hash, |_, (parent, _children)| parent);

        // 5. Check if we arrived at a correct lowest-available node.
        if current_hash != existing.hash {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidProof);
        }

        Ok(())
    }

    /// An interface to insertions and deletions.
    /// Rolls back all changes if encountered an error.
    pub fn update<F,T,E>(&mut self, closure: F) -> Result<T,E>
    where F: FnOnce(&mut Update<M>) -> Result<T,E> {

        let prev_insertions_len = self.insertions.len();

        let mut update = Update {
            forest: self,
            deleted_insertions: Bitarray::with_capacity(prev_insertions_len)
        };

        match closure(&mut update) {
            Ok(result) => {

                // updated nodes on the heap: keep
                // appended nodes to the heap: keep
                // appended insertions: keep
                // insertions marked as deleted: actually delete

                let mut adjustment = 0usize;
                for (i, did_remove) in update.deleted_insertions.iter().enumerate() {
                    if did_remove {
                        update.forest.insertions.remove(i - adjustment);
                        adjustment+=1;
                    }
                }

                Ok(result)
            },
            Err(err) => {

                // updated nodes on the heap: those that became modified - unmark, remove children
                // appended nodes to the heap: truncate
                // appended insertions: truncate
                // insertions marked as deleted: forget the markers

                update.forest.heap.truncate(prev_heap_len);
                update.forest.insertions.truncate(prev_insertions_len);

                update.forest.heap.undo_modifications()
                /// 
                //for (i, ()) in prev_modifications.iter().zip()
                // for index in prev_modifications.xor_iter(&update.forest.modifications).take(prev_heap_len) {
                //     update.forest.heap.update
                // }

                
                Err(err)
            }
        }
        
    }

    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert(&mut self, item: &M) -> Proof {
        self.insertions.push(self.hasher.leaf(item));
        Proof {
            generation: self.generation,
            path: None,
        }
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    /// The algorithm minimizes amount of computation by taking advantage of the already available data.
    pub fn delete(&mut self, item: &M, proof: &Proof) -> Result<(), UtreexoError> {
        if proof.generation != self.generation {
            return Err(UtreexoError::OutdatedProof);
        }

        // Determine the existing node which matches the proof, then verify the rest of the proof,
        // and mark the relevant nodes as modified.

        // 0. Fast check: if the proof relates to a newly added item, simply remove it,
        //    so that transient items do not take up space until normalization.
        let path = match &proof.path {
            Some(path) => path,
            None => {
                // The path is missing, meaning the item must exist among the recent inserions.
                let hash = self.hasher.leaf(item);
                let index = self
                    .find_insertion(&hash)
                    .ok_or(UtreexoError::InvalidProof)?;
                self.insertions.remove(index);
                return Ok(());
            }
        };

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let top = self.root_containing_position(path.position)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != top.level {
            return Err(UtreexoError::InvalidProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        //    And also check the higher-level neighbors in the proof.
        let existing = self.existing_node_for_path(top, &path)?;

        // If the existing node is the leaf, and it's marked as deleted - reject the proof
        if existing.level == 0 && existing.modified {
            return Err(UtreexoError::InvalidProof);
        }

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the bottom node.
        let hasher = &self.hasher;
        let new_children = self.heap.transaction(|mut heap| {
            let item_hash = hasher.leaf(item);

            let (hash, children) = path
                .directions()
                .zip(path.walk_up(item_hash, hasher))
                .enumerate()
                .take(existing.level)
                .fold(
                    (item_hash, None),
                    |(_hash, children), (i, (side, (parent_hash, (left_hash, right_hash))))| {
                        let (left_children, right_children) = side.order(children, None);
                        let (l, r) = (
                            heap.allocate(left_hash, i, left_children),
                            heap.allocate(right_hash, i, right_children),
                        );
                        (parent_hash, Some((l.index, r.index)))
                    },
                );

            // 5. Check if we arrived at a correct lowest-available node.
            if hash != existing.hash {
                // We haven't met the node we expected to meet, so the proof is invalid.
                return Err(UtreexoError::InvalidProof);
            }

            Ok(children)
        })?;

        // Connect children to the existing lower node.
        let _ = self
            .heap
            .update(existing.index, |node| node.children = new_children);

        // Update modification flag for all parents of the deleted leaf.
        // Note: `existing` might be == `top`, so after this call top will pick up new children
        // from the heap where they were written in the above line.
        let top = self.heap.update(top.index, |node| node.modified = true);
        let _ = path.iter().rev().try_fold(top, |node, (side, _)| {
            node.children.map(|(l, r)| {
                self.heap.update(side.choose(l, r).0, |node| {
                    node.modified = true;
                })
            })
        });

        self.deletions += 1;

        Ok(())
    }

    /// Normalizes the forest into minimal number of ordered perfect trees.
    /// Returns a root of the new forst, the forest and a catchup structure.
    pub fn normalize(self) -> (Hash, Forest<M>, Catchup<M>) {
        // TBD: what's the best way to estimate the vector capacity from self.heap.len()?
        let estimated_cap = self.heap.len() / 2 + self.insertions.len();

        // Collect all nodes that were not modified.
        // We delay allocation of the nodes so we don't have to mutably borrow `new_heap`
        // in two iterators, and instead yield pairs `(hash, level)`.
        let non_modified_nodes = self
            .heap
            .traverse(self.roots_iter(), |n| n.modified)
            // 1) add pre-existing unmodified nodes...
            .filter_map(|(_offset, node)| {
                if !node.modified {
                    Some((node.hash, node.level))
                } else {
                    None
                }
            })
            // 2) ...and newly inserted nodes.
            .chain(self.insertions.into_iter().map(|hash| (hash, 0)));

        // we just consumed `self.insertions`, so let's also move out the hasher.
        let hasher = self.hasher;

        // Compute perfect roots for the new tree,
        // joining together same-level nodes into higher-level nodes.
        let (new_heap, new_roots) = non_modified_nodes.fold(
            (
                Heap::with_capacity(estimated_cap),
                [None as Option<NodeIndex>; 64],
            ),
            |(mut new_heap, mut roots), (hash, level)| {
                let mut node = new_heap.allocate(hash, level, None);
                // If we have a left node at the same level already,
                // merge it with the current node.
                // Do the same with the new parent, until it lands on a unoccupied slot.
                while let Some(i) = roots[node.level] {
                    let left = new_heap.node_at(i);
                    node = new_heap.allocate(
                        hasher.intermediate(&left.hash, &node.hash),
                        left.level + 1,
                        Some((left.index, node.index)),
                    );
                    roots[left.level] = None;
                }
                // Place the node in the unoccupied slot.
                roots[node.level] = Some(node.index);
                (new_heap, roots)
            },
        );

        let new_forest = Forest {
            generation: self.generation + 1,
            roots: new_roots,
            insertions: Vec::new(), // will remain empty
            deletions: 0,
            heap: new_heap,
            hasher,
            phantom: self.phantom,
        };

        // Create a new, trimmed forest.
        let trimmed_forest = new_forest.trim();
        let catchup = new_forest.into_catchup();
        let top_root = trimmed_forest.compute_root();

        (top_root, trimmed_forest, catchup)
    }
}

impl<M: MerkleItem> Catchup<M> {
    /// Updates the proof if it's slightly out of date
    /// (made against the previous generation of the Utreexo).
    pub fn update_proof(&self, item: &M, proof: Proof) -> Result<Proof, UtreexoError> {
        // If the proof is already up to date - return w/o changes
        if proof.generation == self.forest.generation {
            return Ok(proof);
        }

        // If the proof is not from the previous generation - fail.
        if self.forest.generation == 0 || proof.generation != (self.forest.generation - 1) {
            return Err(UtreexoError::OutdatedProof);
        }

        // For the newly added items `position` is irrelevant, so we create a dummy placeholder.
        let mut path = proof.path.unwrap_or(Path {
            position: 0,
            neighbors: Vec::new(),
        });

        // Climb up the merkle path until we find an existing node or nothing.
        let hash = self.forest.hasher.leaf(item);
        let (midlevel, catchup_result) = path.walk_up(hash, &self.forest.hasher).fold(
            (0, self.map.get(&hash)),
            |(level, catchup_result), (p, _)| {
                match catchup_result {
                    Some(r) => (level, Some(r)),           // keep the found result
                    None => (level + 1, self.map.get(&p)), // try a higher parent
                }
            },
        );

        // Fail early if we did not find any catchup point.
        let position_offset = catchup_result.ok_or(UtreexoError::InvalidProof)?;

        // Adjust the absolute position:
        // keep the lowest (level+1) bits and add the stored position offset for the stored subtree
        let mask: Position = (1 << midlevel) - 1; // L=0 -> ...00, L=1 -> ...01, L=2 -> ...11
        path.position = position_offset + (path.position & mask);

        // Remove all outdated neighbors
        path.neighbors.truncate(midlevel);

        // Find the root to which the updated position belongs
        let root = self.forest.root_containing_position(path.position)?;

        let directions = Directions {
            position: path.position,
            depth: root.level,
        };
        path.neighbors = self.forest.heap.walk_down(root, directions.rev()).fold(
            path.neighbors,
            |mut list, (_node, new_neighbor)| {
                // TODO: this is not the fastest way to insert missing neighbors
                list.insert(midlevel, new_neighbor.hash);
                list
            },
        );

        Ok(Proof {
            generation: self.forest.generation,
            path: Some(path),
        })
    }

    /// Returns metrics data for this Catchup structure
    pub fn metrics(&self) -> Metrics {
        let mut metrics = self.forest.metrics();
        metrics.memory += mem::size_of::<HashMap<Hash, Position>>()
            + self.map.len() * (mem::size_of::<Hash>() + mem::size_of::<Position>());
        metrics
    }
}

// Internals

impl<M: MerkleItem> Forest<M> {
    /// Returns the index of the tree containing an item at a given position,
    /// and the offset of that tree within the set of all items.
    /// `position-offset` would be the position within that tree.
    fn root_containing_position(&self, position: Position) -> Result<Node, UtreexoError> {
        let mut offset: Position = 0;
        for node in self.roots_iter() {
            offset += node.capacity();
            if position < offset {
                return Ok(node);
            }
        }
        Err(UtreexoError::InvalidProof)
    }

    /// Returns the lowest-available node for a given path and verifies the higher-level
    /// neighbors in the path.
    fn existing_node_for_path(&self, root: Node, path: &Path) -> Result<Node, UtreexoError> {
        self.heap
            .walk_down(root, path.directions().rev())
            .zip(path.neighbors.iter().rev())
            .try_fold(
                root,
                |_parent, ((node, actual_neighbor), proof_neighbor)| {
                    if proof_neighbor != &actual_neighbor.hash {
                        Err(UtreexoError::InvalidProof)
                    } else {
                        Ok(node)
                    }
                },
            )
    }

    /// Capacity of the entire forest as defined by the top-level roots, excluding deletions and insertions.
    fn capacity(&self) -> u64 {
        self.roots_iter().map(|r| r.capacity()).sum()
    }

    /// Returns an iterator over roots of the forest,
    /// from the highest to the lowest level.
    fn roots_iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = Node> + 'a {
        self.roots
            .iter()
            .rev()
            .filter_map(move |optional_index| optional_index.map(|index| self.heap.node_at(index)))
    }

    /// Finds an index of the hash in the list of freshly inserted items.
    fn find_insertion(&self, hash: &Hash) -> Option<usize> {
        self.insertions
            .iter()
            .enumerate()
            .find(|&(_i, ref h)| h == &hash)
            .map(|(i, _h)| i)
    }

    /// Trims the forest leaving only the root nodes.
    /// Assumes the forest is normalized.
    fn trim(&self) -> Forest<M> {
        let mut trimmed_forest = Forest {
            generation: self.generation,
            roots: [None; 64],      // filled in below
            insertions: Vec::new(), // will remain empty
            deletions: 0,
            heap: Heap::with_capacity(64), // filled in below
            hasher: self.hasher.clone(),
            phantom: self.phantom,
        };
        // copy the roots from the new forest to the trimmed forest
        for root in self.roots_iter() {
            let trimmed_root = trimmed_forest.heap.allocate(root.hash, root.level, None);
            trimmed_forest.roots[trimmed_root.level] = Some(trimmed_root.index);
        }
        trimmed_forest
    }

    /// Wraps the forest into a Catchup structure
    fn into_catchup(self) -> Catchup<M> {
        // Traverse the tree to collect the catchup entries
        let catchup_map = self.heap.traverse(self.roots_iter(), |_| true).fold(
            HashMap::<Hash, Position>::new(),
            |mut map, (offset, node)| {
                if node.children == None {
                    map.insert(node.hash, offset);
                }
                map
            },
        );
        Catchup {
            forest: self,
            map: catchup_map,
            phantom: PhantomData,
        }
    }

    /// Hashes the top root of the entire forest, assuming it's normalized.
    /// For that reason, DO NOT expose this method through the API.
    /// Since each root is balanced, the top root is composed of n-1 pairs:
    /// `hash(R3, hash(R2, hash(R1, R0)))`
    fn compute_root(&self) -> Hash {
        self.roots_iter()
            .rev()
            .fold(None, |optional_hash, node| {
                if let Some(h) = optional_hash {
                    // previous hash is of lower level, so it goes to the right
                    Some(self.hasher.intermediate(&node.hash, &h))
                } else {
                    // this is the first iteration - use node's hash as-is
                    Some(node.hash)
                }
            })
            .unwrap_or(self.hasher.empty())
    }
}
