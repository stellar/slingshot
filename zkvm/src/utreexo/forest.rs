use core::borrow::Borrow;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::mem;
use std::rc::Rc;

use super::path::{Directions, NodeHasher, Path, Position, Proof};
use crate::merkle::{Hash, MerkleItem};

/// Forest consists of a number of roots of merkle binary trees.
#[derive(Clone, Serialize, Deserialize)]
pub struct Forest {
    #[serde(with = "crate::serialization::array64")]
    pub(super) roots: [Option<Hash>; 64], // roots of the trees for levels 0 to 63
}

/// Roots of the perfect merkle trees forming a forest, which itself is an imperfect merkle tree.
#[derive(Clone, PartialEq, Debug)]
pub struct WorkForest {
    pub(super) roots: Vec<Rc<Node>>, // roots of all the perfect binary trees, including the newly inserted nodes
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

/// Node in the merkle tree
#[derive(Clone, PartialEq, Debug)]
pub(super) struct Node {
    /// Level of this node. Level 0 is for leaves.
    /// Level N node is a root of a tree over 2^N items.
    pub(super) level: usize,

    /// Merkle hash of this node
    pub(super) hash: Hash,
    /// Flag indicates if any node in the subtree is marked for deletion.
    /// If modified=true for level=0, it means the node is deleted.
    pub(super) modified: bool,
    /// Some(): node has children
    /// None: node is a leaf, or it has no children, only a hash (pruned subtree)
    /// Note that Rc is > 1 only when we are in a `WorkForest::update` block.
    pub(super) children: Option<(Rc<Node>, Rc<Node>)>,
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
        let root_level = find_root(self.roots_iter().map(|(l, _)| l), path.position)
            .ok_or(UtreexoError::InvalidProof)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != root_level {
            return Err(UtreexoError::InvalidProof);
        }

        // 3. Now, walk the merkle proof starting with the leaf,
        //    creating the intermediate hashes until we hit the last neighbor.
        let top_hash = path.iter().take(root_level).fold(
            hasher.leaf(item),
            |curr_hash, (side, neighbor_hash)| {
                let (l, r) = side.order(&curr_hash, neighbor_hash);
                hasher.intermediate(l, r)
            },
        );

        // 4. Check if the computed root matches the stored root.
        if Some(top_hash) != self.roots[root_level] {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidProof);
        }

        Ok(())
    }

    /// Lets use modify the utreexo and yields a new state of the utreexo,
    /// along with a catchup structure.
    pub fn work_forest(&self) -> WorkForest {
        WorkForest {
            roots: self
                .roots_iter()
                .map(|(level, hash)| {
                    Rc::new(Node {
                        level,
                        hash,
                        modified: false,
                        children: None,
                    })
                })
                .collect(),
        }
    }

    /// Lets user to modify the utreexo.
    /// Returns a new state, along with a catchup structure.
    pub fn update<M: MerkleItem>(
        &self,
        hasher: &NodeHasher<M>,
        closure: impl FnOnce(&mut WorkForest) -> Result<(), UtreexoError>,
    ) -> Result<(Self, Catchup), UtreexoError> {
        let mut wforest = self.work_forest();
        let _ = closure(&mut wforest)?;
        let (next_forest, catchup) = wforest.normalize(&hasher);
        Ok((next_forest, catchup))
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
        self.roots.push(Rc::new(Node {
            level: 0,
            hash: hasher.leaf(item),
            modified: false,
            children: None,
        }));
    }

    /// Performs multiple updates in a transactional fashion.
    /// If any update fails, all of the changes are effectively undone.
    pub fn update<F, E>(&mut self, closure: F) -> Result<(), E>
    where
        F: FnOnce(&mut Self) -> Result<(), E>,
    {
        let mut wf = self.clone();

        // If any update fails within a closure, the temporary `wf` is going to be consumed.
        let _ = closure(&mut wf)?;

        // replace the existing work forest with the new, updated one.
        let _ = mem::replace(self, wf);
        Ok(())
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    /// The algorithm minimizes amount of computation by taking advantage of the already available data.
    /// This consumes the forest in case of error, since it may be left in an inconsistent state.
    /// Use `WorkForest::update` to perform updates.
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

    /// Deletes the transient item that does not have a proof.
    fn delete_transient<M: MerkleItem>(
        &mut self,
        item: &M,
        hasher: &NodeHasher<M>,
    ) -> Result<(), UtreexoError> {
        let item_hash = hasher.leaf(item);
        let (index, node) = self
            .roots
            .iter()
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

        Ok(())
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    /// The algorithm minimizes amount of hashing by taking advantage of the already available data.
    /// This consumes the forest in case of error, since it may be left in an inconsistent state.
    /// Use `WorkForest::update` to perform updates.
    fn delete_committed<M: MerkleItem>(
        &mut self,
        item: &M,
        path: &Path,
        hasher: &NodeHasher<M>,
    ) -> Result<(), UtreexoError> {
        // Determine the existing node which matches the proof, then verify the rest of the proof,
        // and mark the relevant nodes as modified.

        // 1. Locate the root under which the item.position is located.
        let top =
            find_root(self.roots.iter_mut(), path.position).ok_or(UtreexoError::InvalidProof)?;
        let top = Rc::make_mut(top);

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != top.level {
            return Err(UtreexoError::InvalidProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        //    And also check the higher-level neighbors in the proof.
        //let existing = top.descend(&path)?;
        let existing = path
            .iter()
            .rev()
            .try_fold(top, |node, (side, neighbor_hash)| {
                if let Some((ref mut l, ref mut r)) = node.children {
                    let (next_node, actual_neighbor) = side.choose(l, r);
                    if &actual_neighbor.hash == neighbor_hash {
                        Ok(Rc::make_mut(next_node))
                    } else {
                        Err(UtreexoError::InvalidProof)
                    }
                } else {
                    Ok(node)
                }
            })?;

        // If the existing node is the leaf, and it's marked as deleted - reject the proof
        if existing.level == 0 && existing.modified {
            return Err(UtreexoError::InvalidProof);
        }

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the bottom node.
        let new_node = path.iter().take(existing.level).fold(
            Node {
                level: 0,
                hash: hasher.leaf(item),
                modified: true,
                children: None,
            },
            |node, (side, neighbor_hash)| {
                let level = node.level;
                let neighbor = Node {
                    level: level,
                    hash: *neighbor_hash,
                    modified: false,
                    children: None,
                };
                let (l, r) = side.order(node, neighbor);
                Node {
                    level: level + 1,
                    hash: hasher.intermediate(&l.hash, &r.hash),
                    modified: true,
                    children: Some((Rc::new(l), Rc::new(r))),
                }
            },
        );

        // 5. Check if we arrived at a correct lowest-available node.
        if new_node.hash != existing.hash {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidProof);
        }

        // 6. Replace the existing node with the newly constructed node.
        //    Note this does not make an unnecessary allocation: the new node exists on the stack.
        //    We simply copy its contents over the heap-allocated `existing_node` behind Rc.
        let _ = mem::replace(existing, new_node);

        // 7. Mark all existing nodes as modified
        let top =
            find_root(self.roots.iter_mut(), path.position).ok_or(UtreexoError::InvalidProof)?;
        let top = Rc::get_mut(top).expect("At this point, there must be uniquely owned top node.");

        path.iter().rev().try_fold(top, |node, (side, _neighbor)| {
            node.modified = true;
            match node.children {
                Some((ref mut l, ref mut r)) => {
                    let node_rc = side.choose(l, r).0;
                    let node = Rc::get_mut(node_rc)
                        .expect("At this point, each node in the chain should be uniquely owned.");
                    Some(node)
                }
                None => None,
            }
        });

        Ok(())
    }

    /// Normalizes the forest into a minimal number of ordered perfect trees.
    /// Returns the new forest and a catchup structure.
    pub fn normalize<M: MerkleItem>(&self, hasher: &NodeHasher<M>) -> (Forest, Catchup) {
        // Tree with modified nodes {d, b, 3, 6}:
        // (a, c have pruned children)
        //  d
        //  |\
        //  a   b   c
        //  |\  |\  |\
        //      2 x     x 7 8 9
        //
        //  |
        //  v
        //
        //  a      c
        //  |\     |\
        //      2      7 8 9
        //
        // The catchup structure is needed to transform higher parts of the proofs
        // against the old tree into the paths within a new tree.
        // Once we moved the childless nodes {a,2,c,7,8,9} somewhere in the new tree,
        // we need to collect a hashmap from their hash into their new offset.

        // 1. Traverse the tree and collect all nodes that were not modified.
        let non_modified_nodes =
            ChildlessNodesIterator::new(self.roots.iter()).filter_map(|(_offset, node_rc)| {
                if node_rc.modified {
                    None
                } else {
                    Some(node_rc.clone())
                }
            });

        // 2. Compute perfect roots for the new tree,
        //    joining together same-level nodes into higher-level nodes.
        let mut new_root_nodes = non_modified_nodes.fold(
            none_64_times::<Rc<Node>>(), // "2^64 of anything should be enough for everyone"
            |mut roots, mut curr_node| {
                let mut store_level = curr_node.level;
                while let Some(left_node) = roots[curr_node.level].take() {
                    curr_node = Rc::new(Node {
                        level: curr_node.level + 1,
                        hash: hasher.intermediate(&left_node.hash, &curr_node.hash),
                        modified: true,
                        children: Some((left_node, curr_node)),
                    });
                    store_level = curr_node.level;
                }
                roots[store_level] = Some(curr_node);
                roots
            },
        );

        // 3. Create the new normalized forest
        let new_forest = Forest {
            roots: new_root_nodes.iter().fold([None; 64], |mut roots, node| {
                if let Some(node) = node {
                    roots[node.level] = Some(node.hash);
                }
                roots
            }),
        };

        // 4. Create the new work forest with new roots.
        //    Note: the roots in the array are ordered by higher-level-last,
        //    but we need to keep bigger trees to the left, so we'll rev() them.
        let new_work_forest = WorkForest {
            // One day Rust will implement IntoIterator for arrays >32 elements.
            // On that day we will do this:
            // new_root_nodes.into_iter().rev().filter_map(|r| r).collect()
            roots: new_root_nodes
                .iter_mut()
                .rev()
                .filter_map(|r| r.take())
                .collect(),
        };

        // 5. Finally, traverse the new forest and collect new positions for all childless nodes
        //    these will be the points of update for the proofs made against the old tree.
        //    All the paths from leaf to these childless nodes remain valid, while the rest of
        //    the path must be computed from
        let catchup_map = ChildlessNodesIterator::new(new_work_forest.roots.iter()).fold(
            HashMap::<Hash, Position>::new(),
            |mut map, (offset, node)| {
                if node.children.is_none() {
                    map.insert(node.hash, offset);
                }
                map
            },
        );

        let catchup = Catchup {
            forest: new_work_forest,
            map: catchup_map,
        };

        (new_forest, catchup)
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

        // 1. Climb up the merkle path until we find an existing node or nothing.
        let leaf_hash = hasher.leaf(item);
        let (midlevel, maybe_offset, _midhash) = path.iter().fold(
            (0, self.map.get(&leaf_hash), leaf_hash),
            |(level, maybe_offset, node_hash), (side, neighbor_hash)| {
                match maybe_offset {
                    // either keep the result we already have...
                    Some(offset) => (level, Some(offset), node_hash),
                    None => {
                        // ...or try finding a higher-level hash
                        let (l, r) = side.order(node_hash, *neighbor_hash);
                        let parent_hash = hasher.intermediate(&l, &r);
                        (level + 1, self.map.get(&parent_hash), parent_hash)
                    }
                }
            },
        );

        // Fail early if we did not find any catchup point.
        let position_offset = maybe_offset.ok_or(UtreexoError::InvalidProof)?;

        // Adjust the absolute position:
        // keep the lowest (level+1) bits and add the stored position offset for the stored subtree
        let mask: Position = (1 << midlevel) - 1; // L=0 -> ...00, L=1 -> ...01, L=2 -> ...11
        path.position = position_offset + (path.position & mask);

        // Remove all outdated neighbors
        path.neighbors.truncate(midlevel);

        // Find the root to which the updated position belongs
        let root =
            find_root(self.forest.roots.iter(), path.position).ok_or(UtreexoError::InvalidProof)?;

        // Construct a new directions object.
        // We cannot take it from path because it does not have all neighbors yet.
        let directions = Directions {
            position: path.position,
            depth: root.level,
        };

        path.neighbors = directions
            .rev()
            .fold(
                (path.neighbors, root),
                |(mut neighbors, mut parent), side| {
                    if let Some((ref l, ref r)) = parent.children {
                        let (trunk, neighbor) = side.choose(l, r);
                        // TODO: this is not the fastest way to insert missing neighbors
                        neighbors.insert(midlevel, neighbor.hash);
                        parent = trunk
                    }
                    (neighbors, parent)
                },
            )
            .0;

        Ok(Proof::Committed(path))
    }
}

impl Node {
    /// maximum number of items in this subtree, ignoring deletions
    pub(super) fn capacity(&self) -> u64 {
        1 << self.level
    }
}

/// Iterator implementing traversal of the binary tree.
/// Note: yields only the nodes without children and their global offset.
struct ChildlessNodesIterator<'a, I>
where
    I: Iterator<Item = &'a Rc<Node>>,
{
    /// reference to the roots
    roots: I,
    /// nodes in the queue - next node to be yielded is in the end of the list
    stack: Vec<(Position, &'a Rc<Node>)>,
    /// offset of the top root
    root_offset: Position,
}

impl<'a, I> ChildlessNodesIterator<'a, I>
where
    I: Iterator<Item = &'a Rc<Node>>,
{
    fn new(roots: I) -> Self {
        Self {
            roots,
            stack: Vec::with_capacity(16),
            root_offset: 0,
        }
    }
}

impl<'a, I> Iterator for ChildlessNodesIterator<'a, I>
where
    I: Iterator<Item = &'a Rc<Node>>,
{
    type Item = (Position, &'a Rc<Node>);
    fn next(&mut self) -> Option<Self::Item> {
        // traverse the current stack of roots until we hit the childless node which we yield.
        while let Some((offset, node)) = self.stack.pop() {
            if let Some((ref l, ref r)) = node.children {
                self.stack.push((offset + node.capacity() / 2, r));
                self.stack.push((offset, l));
            } else {
                return Some((offset, node));
            }
        }
        // when there is nothing else to traverse, try the next root.
        if let Some(root) = self.roots.next() {
            self.stack.push((self.root_offset, root));
            self.root_offset += root.capacity();
            self.next() // this is guaranteed to be 1-level recursion
        } else {
            None
        }
    }
}

fn find_root<T: NodeLevel>(roots: impl IntoIterator<Item = T>, position: Position) -> Option<T> {
    let mut offset: Position = 0;
    for item in roots.into_iter() {
        offset += 1u64 << item.node_level();
        if position < offset {
            return Some(item);
        }
    }
    None
}

trait NodeLevel {
    fn node_level(&self) -> usize;
}

#[rustfmt::skip]
impl<'a> NodeLevel for &'a Rc<Node> {
    fn node_level(&self) -> usize { self.level }
}

#[rustfmt::skip]
impl<'a> NodeLevel for &'a mut Rc<Node> {
    fn node_level(&self) -> usize { self.level }
}

#[rustfmt::skip]
impl NodeLevel for usize {
    fn node_level(&self) -> usize { *self }
}

/// This is a workaround for issue with `[None as Option<T>; N]` where T is not Copy.
/// See https://github.com/rust-lang/rfcs/blob/master/text/2203-const-repeat-expr.md
#[rustfmt::skip]
const fn none_64_times<T>() -> [Option<T>; 64] {
    [
        None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>,
        None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>,
        None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>,
        None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>,
        None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>,
        None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>,
        None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>,
        None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>, None as Option<T>,
    ]
}
