use core::borrow::Borrow;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem;

use super::nodes::{Heap, Node, NodeHasher, NodeIndex};
use super::path::{Directions, Path, Position, Proof};
use crate::merkle::{Hash, MerkleItem};

/// Forest consists of a number of roots of merkle binary trees.
#[derive(Clone, Serialize, Deserialize)]
pub struct Forest {
    #[serde(with = "crate::serialization::array64")]
    roots: [Option<Hash>; 64], // roots of the trees for levels 0 to 63
}

/// State of the Utreexo forest during update
#[derive(Clone, Serialize, Deserialize)]
pub struct WorkForest {
    roots: Vec<NodeIndex>, // roots of all the trees including the newly inserted nodes
    heap: Heap,
}

/// Structure that helps auto-updating the proofs created for a previous state of a forest.
#[derive(Clone, Serialize, Deserialize)]
pub struct Catchup {
    forest: WorkForest,           // forest that stores the inner nodes
    map: HashMap<Hash, Position>, // node hash -> new position offset for this node
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

impl Forest {
    /// Creates a new instance of Forest.
    pub fn new() -> Self {
        Forest { roots: [None; 64] }
    }

    /// Total number of items in the forest.
    pub fn count(&self) -> u64 {
        self.roots_iter()
            .fold(0u64, |total, (level, _)| total + (1 << level))
    }

    /// Verifies the item's proof of inclusion.
    pub fn verify<M: MerkleItem>(
        &self,
        item: &M,
        proof: &Proof,
        hasher: &NodeHasher<M>,
    ) -> Result<(), UtreexoError> {
        let path = match proof {
            Proof::Transient => return Err(UtreexoError::InvalidProof),
            Proof::Committed(path) => path,
        };

        // 1. Locate the root under which the item.position is located.
        let (root_level, _) =
            Node::find_root(self.roots_iter(), |&(level, _)| level, path.position)
                .ok_or(UtreexoError::InvalidProof)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != root_level {
            return Err(UtreexoError::InvalidProof);
        }

        // 3. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the root.
        let current_hash = hasher.leaf(item);
        let current_hash = path
            .walk_up(current_hash, &hasher)
            .take(root_level)
            .fold(current_hash, |_, (parent, _children)| parent);

        // 4. Check if the computed root matches the stored root.
        if Some(current_hash) != self.roots[root_level] {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidProof);
        }

        Ok(())
    }

    /// Lets use modify the utreexo and yields a new state of the utreexo,
    /// along with a catchup structure.
    pub fn work_forest(&self) -> WorkForest {
        let mut heap = Heap::with_capacity(64);

        // Convert the root hashes into the nodes
        let roots = self
            .roots_iter()
            .map(|(level, hash)| heap.allocate(hash, level, None).index)
            .collect();

        WorkForest { roots, heap }
    }

    /// Lets user to modify the utreexo.
    /// Returns a new state, along with a catchup structure.
    pub fn update<F, T, M>(
        &self,
        hasher: &NodeHasher<M>,
        closure: F,
    ) -> Result<(T, Self, Catchup), UtreexoError>
    where
        F: FnOnce(&mut WorkForest) -> Result<T, UtreexoError>,
        M: MerkleItem,
    {
        let mut forest = self.work_forest();
        let result = closure(&mut forest)?;
        let (next_utreexo, catchup) = forest.normalize(&hasher);
        Ok((result, next_utreexo, catchup))
    }

    /// Since each root is balanced, the top root is composed of n-1 pairs:
    /// `hash(R3, hash(R2, hash(R1, R0)))`
    pub fn root<M: MerkleItem>(&self, hasher: &NodeHasher<M>) -> Hash {
        self.roots_iter()
            .rev()
            .fold(None, |optional_hash, (_level, hash2)| {
                if let Some(hash1) = optional_hash {
                    // previous hash is of lower level, so it goes to the right
                    Some(hasher.intermediate(&hash2, &hash1))
                } else {
                    // this is the first iteration - use node's hash as-is
                    Some(hash2)
                }
            })
            .unwrap_or(hasher.empty())
    }

    /// Returns an iterator over roots of the forest,
    /// from the highest to the lowest level.
    fn roots_iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = (usize, Hash)> + 'a {
        self.roots
            .iter()
            .enumerate()
            .rev()
            .filter_map(|(level, optional_hash)| optional_hash.map(|hash| (level, hash)))
    }
}

impl WorkForest {
    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert<M: MerkleItem>(&mut self, item: &M, hasher: &NodeHasher<M>) {
        let hash = hasher.leaf(item);
        self.roots.push(self.heap.allocate(hash, 0, None).index);
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    /// The algorithm minimizes amount of computation by taking advantage of the already available data.
    pub fn delete<M: MerkleItem, P: Borrow<Proof>>(
        &mut self,
        item: &M,
        proof: P,
        hasher: &NodeHasher<M>,
    ) -> Result<(), UtreexoError> {
        match proof.borrow() {
            Proof::Transient => self.delete_transient(item, hasher),
            Proof::Committed(path) => self.delete_committed(item, path, hasher),
        }
    }

    /// Deletes the transient item that does not have a proof
    fn delete_transient<M: MerkleItem>(
        &mut self,
        item: &M,
        hasher: &NodeHasher<M>,
    ) -> Result<(), UtreexoError> {
        let item_hash = hasher.leaf(item);
        let (index, node) = self
            .roots_iter()
            .enumerate()
            .find(|&(_i, node)| node.level == 0 && node.hash == item_hash)
            .ok_or(UtreexoError::InvalidProof)?;

        // If the node was already marked as modified - fail.
        // This may happen if it was a previously stored node with a proof, but part of a 1-node tree;
        // when such node is deleted via `delete_committed`, it is simply marked as modified.
        // To prevent double-spending, we need to check that flag here.
        if node.modified {
            return Err(UtreexoError::InvalidProof);
        }
        self.roots.remove(index);
        return Ok(());
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    /// The algorithm minimizes amount of computation by taking advantage of the already available data.
    fn delete_committed<M: MerkleItem>(
        &mut self,
        item: &M,
        path: &Path,
        hasher: &NodeHasher<M>,
    ) -> Result<(), UtreexoError> {
        // Determine the existing node which matches the proof, then verify the rest of the proof,
        // and mark the relevant nodes as modified.

        // 1. Locate the root under which the item.position is located.
        let top = Node::find_root(self.roots_iter(), |&node| node.level, path.position)
            .ok_or(UtreexoError::InvalidProof)?;

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
        //    Note, it is fine if we fail mid-way updating the state -
        //    it will be completely discarded by `Utreexo::update`.
        let item_hash = hasher.leaf(item);

        let (hash, new_children) = path
            .directions()
            .zip(path.walk_up(item_hash, &hasher))
            .enumerate()
            .take(existing.level)
            .fold(
                (item_hash, None),
                |(_hash, children), (i, (side, (parent_hash, (left_hash, right_hash))))| {
                    let (left_children, right_children) = side.order(children, None);
                    let (l, r) = (
                        self.heap.allocate(left_hash, i, left_children),
                        self.heap.allocate(right_hash, i, right_children),
                    );
                    (parent_hash, Some((l.index, r.index)))
                },
            );

        // 5. Check if we arrived at a correct lowest-available node.
        if hash != existing.hash {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidProof);
        }

        // Connect children to the existing lower node.
        let _ = self
            .heap
            .update(existing.index, |node| node.children = new_children);

        // Update modification flag for all parents of the deleted leaf.
        // Note: `existing` might be equal to `top`, so after this call `top` will pick up new children
        // from the heap where they were written in the above line.
        let top = self.heap.update(top.index, |node| {
            node.modified = true;
        });
        let _ = path.iter().rev().try_fold(top, |node, (side, _)| {
            node.children.map(|(l, r)| {
                self.heap.update(side.choose(l, r).0, |node| {
                    node.modified = true;
                })
            })
        });

        Ok(())
    }

    /// Allows performing multiple updates atomically.
    pub fn transaction<F, T, E>(&mut self, closure: F) -> Result<T, E>
    where
        F: FnOnce(&mut Self) -> Result<T, E>,
    {
        // TBD: make this more efficient via custom copy-on-write.
        let mut wf = self.clone();

        // if the closure fails, the temporary `wf` is going to be thrown away.
        let result = closure(&mut wf)?;

        // replace the existing work forest with the new, updated one.
        mem::replace(self, wf);
        Ok(result)
    }

    /// Normalizes the forest into minimal number of ordered perfect trees.
    /// Returns a root of the new forst, the forest and a catchup structure.
    pub fn normalize<M: MerkleItem>(self, hasher: &NodeHasher<M>) -> (Forest, Catchup) {
        // TBD: what's the best way to estimate the vector capacity from self.heap.len()?
        let estimated_cap = self.heap.len() / 2;

        // Collect all nodes that were not modified.
        // We delay allocation of the nodes so we don't have to mutably borrow `new_heap`
        // in two iterators, and instead yield pairs `(hash, level)`.
        let non_modified_nodes = self
            .heap
            .traverse(self.roots_iter(), |n| n.modified)
            .filter_map(|(_offset, node)| {
                if !node.modified {
                    Some((node.hash, node.level))
                } else {
                    None
                }
            });

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

        let new_forest = WorkForest {
            roots: new_roots.iter().rev().filter_map(|r| *r).collect(),
            heap: new_heap,
        };

        let utreexo_roots = new_roots.iter().fold([None; 64], |mut roots, ni| {
            if let Some(ni) = ni {
                let node = new_forest.heap.node_at(*ni);
                roots[node.level] = Some(node.hash);
            }
            roots
        });
        let utreexo = Forest {
            roots: utreexo_roots,
        };

        let catchup_map = new_forest
            .heap
            .traverse(new_forest.roots_iter(), |_| true)
            .fold(
                HashMap::<Hash, Position>::new(),
                |mut map, (offset, node)| {
                    if node.children == None {
                        map.insert(node.hash, offset);
                    }
                    map
                },
            );
        let catchup = Catchup {
            forest: new_forest,
            map: catchup_map,
        };

        (utreexo, catchup)
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

    /// Returns an iterator over roots of the forest,
    /// from the highest to the lowest level.
    fn roots_iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = Node> + 'a {
        self.roots
            .iter()
            .map(move |&index| self.heap.node_at(index))
    }
}

impl Catchup {
    /// Updates the proof if it's slightly out of date
    /// (made against the previous state of the Utreexo).
    pub fn update_proof<M: MerkleItem>(
        &self,
        item: &M,
        proof: Proof,
        hasher: &NodeHasher<M>,
    ) -> Result<Proof, UtreexoError> {
        let mut path = match proof {
            // For the transient items `position` is irrelevant, so we may as well use 0.
            Proof::Transient => Path::default(),
            Proof::Committed(path) => path,
        };

        // Climb up the merkle path until we find an existing node or nothing.
        let hash = hasher.leaf(item);
        let (midlevel, catchup_result) = path.walk_up(hash, &hasher).fold(
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
        let root = Node::find_root(self.forest.roots_iter(), |&node| node.level, path.position)
            .ok_or(UtreexoError::InvalidProof)?;

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

        Ok(Proof::Committed(path))
    }
}
