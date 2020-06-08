use core::borrow::Borrow;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::mem;

use thiserror::Error;

use super::heap::{Heap, HeapIndex};
use zkvm::merkle::{Directions, Hash, Hasher, MerkleItem, MerkleTree, Path, Position};

/// Forest consists of a number of roots of merkle binary trees.
#[derive(Clone, Serialize, Deserialize)]
pub struct Forest {
    #[serde(with = "array64")]
    pub(super) roots: [Option<Hash>; 64], // roots of the trees for levels 0 to 63
}

/// Roots of the perfect merkle trees forming a forest, which itself is an imperfect merkle tree.
#[derive(Clone, Serialize, Deserialize)]
pub struct WorkForest {
    roots: Vec<HeapIndex>, // roots of all the perfect binary trees, including the newly inserted nodes
    heap: Heap<Node>,
}

/// Structure that helps auto-updating the proofs created for a previous state of a forest.
#[derive(Clone, Serialize, Deserialize)]
pub struct Catchup {
    forest: WorkForest,           // forest that stores the inner nodes
    map: HashMap<Hash, Position>, // node hash -> new position offset for this node
}

/// Represents an error in proof creation, verification, or parsing.
#[derive(Error, Clone, Debug, Eq, PartialEq)]
pub enum UtreexoError {
    /// This error occurs when we receive a proof that's outdated and cannot be auto-updated.
    #[error("Item proof is outdated and must be re-created against the new state")]
    OutdatedProof,

    /// This error occurs when the merkle proof is too short or too long, or does not lead to a node
    /// to which it should.
    #[error("Merkle proof is invalid")]
    InvalidProof,
}

/// Node in the merkle tree
#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub(super) struct Node {
    /// Level of this node. Level 0 is for leaves.
    /// Level N node is a root of a tree over 2^N items.
    level: usize,

    /// Merkle hash of this node
    hash: Hash,
    /// Flag indicates if any node in the subtree is marked for deletion.
    /// If modified=true for level=0, it means the node is deleted.
    modified: bool,
    /// Some(): node has children
    /// None: node is a leaf, or it has no children, only a hash (pruned subtree)
    /// Note that Rc is > 1 only when we are in a `WorkForest::update` block.
    children: Option<(HeapIndex, HeapIndex)>,
}

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
    /// Converts the proof to path.
    /// Returns None for Transient proof.
    pub fn as_path(&self) -> Option<&Path> {
        match self {
            Proof::Transient => None,
            Proof::Committed(path) => Some(path),
        }
    }
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

    /// Verifies that the given item and a path belong to the forest.
    pub fn verify<M: MerkleItem>(
        &self,
        item: &M,
        path: &Path,
        hasher: &Hasher<M>,
    ) -> Result<(), UtreexoError> {
        let computed_root = path.compute_root(item, hasher);
        if let Some((_i, level)) =
            find_root(self.roots_iter().map(|(level, _)| level), path.position)
        {
            // unwrap won't fail because `find_root` returns level for the actually existing root.
            if self.roots[level].unwrap() == computed_root {
                return Ok(());
            }
        }
        Err(UtreexoError::InvalidProof)
    }

    /// Lets use modify the utreexo and yields a new state of the utreexo,
    /// along with a catchup structure.
    pub fn work_forest(&self) -> WorkForest {
        let mut heap = Heap::new();
        let roots = self
            .roots_iter()
            .map(|(level, hash)| {
                heap.allocate(Node {
                    level,
                    hash,
                    modified: false,
                    children: None,
                })
            })
            .collect();
        WorkForest { roots, heap }
    }

    /// Since each root is balanced, the top root is composed of n-1 pairs:
    /// `hash(R3, hash(R2, hash(R1, R0)))`
    pub fn root<M: MerkleItem>(&self, hasher: &Hasher<M>) -> Hash {
        MerkleTree::connect_perfect_roots(self.roots.iter().filter_map(|r| *r), &hasher)
    }

    /// Returns an iterator over roots of the forest as (level, hash) pairs,
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
    pub fn insert<M: MerkleItem>(&mut self, item: &M, hasher: &Hasher<M>) {
        self.roots.push(self.heap.allocate(Node {
            level: 0,
            hash: hasher.leaf(item),
            modified: false,
            children: None,
        }));
    }

    /// Performs multiple updates in a transactional fashion.
    /// If any update fails, all of the changes are effectively undone.
    pub fn batch<F, E>(&mut self, closure: F) -> Result<&mut Self, E>
    where
        F: FnOnce(&mut Self) -> Result<(), E>,
    {
        let prev_roots = self.roots.clone();
        let checkpoint = self.heap.checkpoint();

        match closure(self) {
            Ok(_) => {
                self.heap.commit(checkpoint);
                Ok(self)
            }
            Err(e) => {
                self.heap.rollback(checkpoint);
                self.roots = prev_roots;
                Err(e)
            }
        }
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    /// The algorithm minimizes amount of computation by taking advantage of the already available data.
    /// This consumes the forest in case of error, since it may be left in an inconsistent state.
    /// Use `WorkForest::update` to perform updates.
    pub fn delete<M: MerkleItem, P: Borrow<Proof>>(
        &mut self,
        item: &M,
        proof: P,
        hasher: &Hasher<M>,
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
        hasher: &Hasher<M>,
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
        hasher: &Hasher<M>,
    ) -> Result<(), UtreexoError> {
        // Determine the existing node which matches the proof, then verify the rest of the proof,
        // and mark the relevant nodes as modified.

        // 1. Locate the root under which the item.position is located.
        let top_position = find_root(self.roots_iter().map(|r| r.level), path.position)
            .ok_or(UtreexoError::InvalidProof)?
            .0;

        let top_index = &mut self.roots[top_position]; // get the updateable ref to the index
        self.heap.make_mut(top_index); // update the index to CoW'd one (if needed).
        let top_index = *top_index; // copy out the updated index

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != self.heap.get_ref(top_index).level {
            return Err(UtreexoError::InvalidProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        //    And also check the higher-level neighbors in the proof.
        let existing_index =
            path.iter()
                .rev()
                .try_fold(top_index, |node_index, (side, neighbor_hash)| {
                    if let Some((l, r)) = self.heap.get_ref(node_index).children {
                        let (mut next_node, actual_neighbor) = side.order(l, r);
                        if &self.heap.get_ref(actual_neighbor).hash == neighbor_hash {
                            // CoW the next node
                            self.heap.make_mut(&mut next_node);
                            // update the parent node's reference.
                            let mut parent = self
                                .heap
                                .get_mut(node_index)
                                .expect("traversing down - parent node is already CoW-ed");
                            parent.children = Some(side.order(next_node, actual_neighbor));
                            Ok(next_node)
                        } else {
                            Err(UtreexoError::InvalidProof)
                        }
                    } else {
                        Ok(node_index)
                    }
                })?;

        // If the existing node is the leaf, and it's marked as deleted - reject the proof
        let existing = self.heap.get_ref(existing_index).clone();
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
                    children: Some((self.heap.allocate(l), self.heap.allocate(r))),
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
        let _ = mem::replace(
            self.heap
                .get_mut(existing_index)
                .expect("replacing midlevel - already CoW'd"),
            new_node,
        );

        // 7. Mark all existing nodes as modified

        let top_index = self.roots[find_root(self.roots_iter().map(|r| r.level), path.position)
            .ok_or(UtreexoError::InvalidProof)?
            .0];

        // 8. Mark all nodes in the path as modified.
        path.iter()
            .rev()
            .try_fold(top_index, |node_index, (side, _neighbor)| {
                let node = self
                    .heap
                    .get_mut(node_index)
                    .expect("marking as modified - already CoW'd");
                node.modified = true;
                match node.children {
                    Some((l, r)) => {
                        let (child_index, _neighbor) = side.order(l, r);
                        Some(child_index)
                    }
                    None => None,
                }
            });

        Ok(())
    }

    /// Normalizes the forest into a minimal number of ordered perfect trees.
    /// Returns the new forest and a catchup structure.
    pub fn normalize<M: MerkleItem>(&self, hasher: &Hasher<M>) -> (Forest, Catchup) {
        // Tree with modified nodes {d, b, 3, 6}, while {a, c} have pruned children:
        //
        //  d
        //  |\
        //  a   b   c              ---->   a      c
        //  |\  |\  |\                     |\     |\
        //      2 x     x 7 8 9                2      7 8 9
        //
        // The catchup structure is needed to transform higher parts of the proofs
        // against the old tree into the paths within a new tree.
        // Once we moved the childless nodes {a,2,c,7,8,9} somewhere in the new tree,
        // we need to collect a hashmap from their hashes into their new offsets.

        // 1. Traverse the tree and collect all nodes that were not modified.
        let mut non_modified_nodes = Vec::<HeapIndex>::new();
        let mut new_heap = Heap::<Node>::new();

        for node in ChildlessNodesIterator::new(&self.heap, self.roots.iter()).filter_map(
            |(_offset, node)| {
                if node.modified {
                    None
                } else {
                    Some(node)
                }
            },
        ) {
            assert!(node.children.is_none());
            let node_index = new_heap.allocate(node);
            non_modified_nodes.push(node_index);
        }

        // 2. Compute perfect roots for the new tree,
        //    joining together same-level nodes into higher-level nodes.
        let new_root_nodes = non_modified_nodes.into_iter().fold(
            [None as Option<HeapIndex>; 64], // "2^64 of anything should be enough for everyone"]
            |mut roots, mut curr_node_index| {
                let mut curr_level = new_heap.get_ref(curr_node_index).level;
                while let Some(left_node_index) = roots[curr_level].take() {
                    let left_node_hash = new_heap.get_ref(left_node_index).hash;
                    curr_node_index = new_heap.allocate(Node {
                        level: curr_level + 1,
                        hash: hasher
                            .intermediate(&left_node_hash, &new_heap.get_ref(curr_node_index).hash),
                        modified: true,
                        children: Some((left_node_index, curr_node_index)),
                    });
                    curr_level += 1;
                }
                roots[curr_level] = Some(curr_node_index);
                roots
            },
        );

        // 3. Create the new normalized forest
        let new_forest = Forest {
            roots: new_root_nodes.iter().fold([None; 64], |mut roots, ni| {
                if let Some(ni) = ni {
                    let node = new_heap.get_ref(*ni);
                    roots[node.level] = Some(node.hash);
                }
                roots
            }),
        };

        // 4. Create the new work forest with new roots.
        //    Note: the roots in the array are ordered by higher-level-last,
        //    but we need to keep bigger trees to the left, so we'll rev() them.
        let new_work_forest = WorkForest {
            roots: new_root_nodes
                .iter()
                .rev()
                .filter_map(|r| r.as_ref().take())
                .copied()
                .collect(),
            heap: new_heap,
        };

        // 5. Finally, traverse the new forest and collect new positions for all childless nodes
        //    these will be the points of update for the proofs made against the old tree.
        //    All the paths from leaf to these childless nodes remain valid, while the rest of
        //    the path must be computed from
        let catchup_map =
            ChildlessNodesIterator::new(&new_work_forest.heap, new_work_forest.roots.iter()).fold(
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

    fn roots_iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = &Node> + 'a {
        self.roots.iter().map(move |i| self.heap.get_ref(*i))
    }
}

impl Catchup {
    /// Updates the proof if it's slightly out of date
    /// (made against the previous state of the Utreexo).
    pub fn update_proof<M: MerkleItem>(
        &self,
        item: &M,
        proof: Proof,
        hasher: &Hasher<M>,
    ) -> Result<Proof, UtreexoError> {
        Ok(match proof {
            // if the proof was transient, it may be updated (if item got committed),
            // or may remain transient (if it did not).
            Proof::Transient => self
                .update_path(item, Path::default(), hasher)
                .map_or(Proof::Transient, |path| Proof::Committed(path)),
            // if the proof was committed and we fail to update it, it means it was invalid.
            Proof::Committed(path) => Proof::Committed(
                self.update_path(item, path, hasher)
                    .ok_or(UtreexoError::InvalidProof)?,
            ),
        })
    }

    /// Returns an updated path. Returns None if the item pointed to by a path was not committed.
    fn update_path<M: MerkleItem>(
        &self,
        item: &M,
        mut path: Path,
        hasher: &Hasher<M>,
    ) -> Option<Path> {
        // 1. Climb up the merkle path until we find an existing node or nothing.
        let leaf_hash = hasher.leaf(item);
        let (midlevel, maybe_offset, _midhash) = path.iter().fold(
            (0, self.map.get(&leaf_hash), leaf_hash),
            |(level, maybe_offset, node_hash), (side, neighbor_hash)| {
                if let Some(offset) = maybe_offset {
                    // either keep the result we already have...
                    (level, Some(offset), node_hash)
                } else {
                    // ...or try finding a higher-level hash
                    let (l, r) = side.order(node_hash, *neighbor_hash);
                    let parent_hash = hasher.intermediate(&l, &r);
                    (level + 1, self.map.get(&parent_hash), parent_hash)
                }
            },
        );

        // Fail early if we did not find any catchup point.
        let position_offset = maybe_offset?;

        // Adjust the absolute position:
        // keep the lowest (level+1) bits and add the stored position offset for the stored subtree
        let mask: Position = (1 << midlevel) - 1; // L=0 -> ...00, L=1 -> ...01, L=2 -> ...11
        path.position = position_offset + (path.position & mask);

        // Remove all outdated neighbors
        path.neighbors.truncate(midlevel);

        // Find the root to which the updated position belongs
        let root_index = self.forest.roots
            [find_root(self.forest.roots_iter().map(|r| r.level), path.position)?.0];

        // Construct a new directions object.
        // We cannot take it from path because it does not have all neighbors yet.
        let directions = Directions::new(path.position, self.forest.heap.get_ref(root_index).level);

        path.neighbors = directions
            .rev()
            .fold(
                (path.neighbors, root_index),
                |(mut neighbors, mut parent_index), side| {
                    if let Some((l, r)) = self.forest.heap.get_ref(parent_index).children {
                        let (trunk, neighbor) = side.order(l, r);
                        // TODO: this is not the fastest way to insert missing neighbors
                        neighbors.insert(midlevel, self.forest.heap.get_ref(neighbor).hash);
                        parent_index = trunk;
                    }
                    (neighbors, parent_index)
                },
            )
            .0;

        Some(path)
    }
}

/// Iterator implementing traversal of the binary tree.
/// Note: yields only the nodes without children and their global offset.
struct ChildlessNodesIterator<'h, I>
where
    I: Iterator,
    I::Item: Borrow<HeapIndex>,
{
    /// reference to the heap containing the nodes
    heap: &'h Heap<Node>,
    /// reference to the roots
    roots: I,
    /// nodes in the queue - next node to be yielded is in the end of the list
    stack: Vec<(Position, HeapIndex)>,
    /// offset of the top root
    root_offset: Position,
}

impl<'h, I> ChildlessNodesIterator<'h, I>
where
    I: Iterator,
    I::Item: Borrow<HeapIndex>,
{
    fn new(heap: &'h Heap<Node>, roots: I) -> Self {
        Self {
            heap,
            roots,
            stack: Vec::with_capacity(16),
            root_offset: 0,
        }
    }
}

impl<'h, I> Iterator for ChildlessNodesIterator<'h, I>
where
    I: Iterator,
    I::Item: Borrow<HeapIndex>,
{
    type Item = (Position, Node);
    fn next(&mut self) -> Option<Self::Item> {
        // traverse the current stack of roots until we hit the childless node which we yield.
        while let Some((offset, node_index)) = self.stack.pop() {
            let node = self.heap.get_ref(node_index);
            if let Some((l, r)) = node.children {
                self.stack.push((offset + (1 << node.level) / 2, r));
                self.stack.push((offset, l));
            } else {
                return Some((offset, node.clone()));
            }
        }
        // when there is nothing else to traverse, try the next root.
        if let Some(root_index) = self.roots.next() {
            let i = *root_index.borrow();
            let root = self.heap.get_ref(i);
            self.stack.push((self.root_offset, i));
            self.root_offset += 1 << root.level;
            self.next() // this is guaranteed to be 1-level recursion
        } else {
            None
        }
    }
}

/// Scans the list of roots' levels and returns the index and the level of the root that contains the position in a tree.
fn find_root(roots: impl IntoIterator<Item = usize>, position: Position) -> Option<(usize, usize)> {
    let mut offset: Position = 0;
    for (i, level) in roots.into_iter().enumerate() {
        offset += 1u64 << level;
        if position < offset {
            return Some((i, level));
        }
    }
    None
}

impl fmt::Debug for Forest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "utreexo::Forest{{\n")?;
        for (level, root) in self
            .roots
            .iter()
            .enumerate()
            .rev()
            .skip_while(|(_, &x)| x.is_none())
        {
            write!(
                f,
                "  [{}] {}\n",
                level,
                root.as_ref()
                    .map(|r| hex::encode(&r))
                    .unwrap_or_else(|| "none".to_string())
            )?;
        }
        write!(f, "}}")
    }
}

impl fmt::Debug for WorkForest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "utreexo::WorkForest{{\n")?;
        for root in self.roots.iter() {
            self.heap.get_ref(*root).debug_fmt(&self.heap, f, "    ")?;
        }
        write!(f, "}}")
    }
}

impl Node {
    fn debug_fmt(
        &self,
        heap: &Heap<Node>,
        f: &mut fmt::Formatter<'_>,
        indent: &str,
    ) -> fmt::Result {
        write!(
            f,
            "{}[{}] {} ({})\n",
            indent,
            if self.modified { "x" } else { " " },
            hex::encode(&self.hash),
            self.level
        )?;
        if let Some((l, r)) = self.children {
            heap.get_ref(l)
                .debug_fmt(heap, f, &(indent.to_owned() + "    "))?;
            heap.get_ref(r)
                .debug_fmt(heap, f, &(indent.to_owned() + "    "))?;
        }
        Ok(())
    }
}

/// Serde adaptor for 64-item array
mod array64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<T, S>(value: &[T; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        T: Serialize + Clone,
        S: Serializer,
    {
        value.to_vec().serialize(serializer)
    }

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<[T; 64], D::Error>
    where
        D: Deserializer<'de>,
        T: Deserialize<'de> + Default,
    {
        let mut vec = Vec::<T>::deserialize(deserializer)?;
        if vec.len() != 64 {
            return Err(serde::de::Error::invalid_length(
                vec.len(),
                &"a 64-item array",
            ));
        }
        let mut buf: [T; 64] = [
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
            T::default(),
        ];
        for i in 0..64 {
            buf[63 - i] = vec.pop().unwrap();
        }
        Ok(buf)
    }
}
