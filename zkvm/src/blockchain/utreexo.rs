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
use merlin::Transcript;
use std::collections::HashMap;

/// Merkle hash of a node
pub type Hash = [u8; 32];

/// Absolute position of an item in the tree.
pub type Position = u64;

/// Merkle proof of inclusion of a node in a `Forest`.
/// The exact tree is determined by the `position`, an absolute position of the item
/// within the set of all items in the forest.
/// Neighbors are counted from lowest to the highest.
/// Left/right position of the neighbor is determined by the appropriate bit in `position`.
/// (Lowest bit=1 means the first neighbor is to the left of the node.)
/// `generation` points to the generation of the Forest to which the proof applies.
/// `path` is None if this proof is for a newly added item that has no merkle path yet.
pub struct Proof {
    /// Generation of the forest to which the proof applies.
    pub generation: u64,

    /// Merkle path to the item. If missing, the proof applies to a yet-to-be-normalized forest.
    pub path: Option<Path>,
}

/// Merkle path to the item.
pub struct Path {
    position: Position,
    neighbors: Vec<Hash>,
}

/// Forest contains some number of perfect merkle binary trees
/// and a list of newly added items.
#[derive(Clone)]
pub struct Forest {
    generation: u64,
    roots: [Option<NodeIndex>; 64], // roots of the trees for levels 0 to 63
    insertions: HashMap<Hash, ()>,  // new items
    deletions: usize,
    heap: Heap,
    hasher: NodeHasher,
}

/// Structure that helps auto-updating the proofs created for a previous generation of a forest.
#[derive(Clone)]
pub struct Catchup {
    forest: Forest,               // forest that stores the nodes
    map: HashMap<Hash, Position>, // node hash -> new position offset for this node
}

/// Metrics of the Forest.
#[derive(Copy, Clone, PartialEq, Debug)]
pub struct Metrics {
    /// Generation of the forest
    pub generation: u64,

    /// Total number of items
    pub count: usize,

    /// Number of deletions
    pub deletions: usize,

    /// Number of insertions
    pub insertions: usize,
}

/// Index of a `Node` within a forest's heap storage.
type NodeIndex = usize;

/// Node represents a leaf or an intermediate node in one of the trees.
/// Leaves are indicated by `level=0`.
/// Leaves and trimmed nodes have `children=None`.
/// Root nodes have `parent=None`.
#[derive(Copy, Clone, PartialEq, Debug)]
struct Node {
    hash: Hash,
    index: NodeIndex,
    level: usize,
    modified: bool,
    children: Option<(NodeIndex, NodeIndex)>,
}

/// Packed node as stored in memory.
/// 32 bytes for hash, plus 13 bytes for metadata and parent and children indexes.
/// Flags are: 6 bits for the level 0..63, 1 bit for "modified" and 1 bit for "has children".
#[derive(Copy, Clone, PartialEq, Debug)]
struct PackedNode {
    hash: Hash,
    flags: u8,
    children: (u32, u32),
}

/// Storage of all the nodes with methods to access them.
#[derive(Clone)]
struct Heap {
    offset: NodeIndex, // ≥0 for temporary heap that extends this one after proof validation
    heap: Vec<PackedNode>,
}

/// Precomputed instance for hashing the nodes
#[derive(Clone)]
struct NodeHasher {
    transcript: Transcript,
}

/// Represents an error in proof creation, verification, or parsing.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum UtreexoError {
    /// This error occurs when we receive a proof that's outdated and cannot be auto-updated.
    #[fail(display = "Item proof is outdated and must be re-created against the new state")]
    OutdatedProof,

    /// This error occurs when we the item in the proof is out of bounds
    #[fail(display = "Item proof contains position that is out of bounds")]
    ItemOutOfBounds,

    /// This error occurs when the merkle proof is too short or too long, or does not lead to a node
    /// to which it should.
    #[fail(display = "Merkle proof is invalid")]
    InvalidMerkleProof,

    /// This error occurs when the Utreexo state is found in inconsistent/unexpected shape.
    #[fail(display = "Utreexo is inconsistent!")]
    InternalInconsistency,

    /// This error occurs when too many changes are stored for internal representation to handle.
    #[fail(display = "Utreexo is out of capacity")]
    ExceedingCapacity,
}

impl Forest {
    /// Creates a new empty Forest.
    pub fn new() -> Forest {
        Forest {
            generation: 0,
            roots: [None; 64],
            insertions: HashMap::new(),
            deletions: 0,
            heap: Heap::new(),
            hasher: NodeHasher::new(),
        }
    }

    /// Returns metrics data for this Forest
    pub fn metrics(&self) -> Metrics {
        let trees_sum: u64 = self.roots_iter().map(|r| r.capacity()).sum();
        Metrics {
            generation: self.generation,
            count: (trees_sum as usize) + self.insertions.len() - self.deletions,
            deletions: self.deletions,
            insertions: self.insertions.len(),
        }
    }

    /// Verifies the item's proof of inclusion.
    pub fn verify<M: MerkleItem>(&self, item: &M, proof: &Proof) -> Result<(), UtreexoError> {
        if proof.generation != self.generation {
            return Err(UtreexoError::OutdatedProof);
        }

        // 0. Fast check: if the proof relates to a newly added item.
        let path = match &proof.path {
            Some(path) => path,
            None => {
                let hash = Node::hash_leaf(self.hasher.clone(), item);
                return self
                    .insertions
                    .get(&hash)
                    .map(|x| *x)
                    .ok_or(UtreexoError::InvalidMerkleProof);
            }
        };

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let top = self.root_containing_position(path.position)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != top.level {
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        //    And also check the higher-level neighbors in the proof.
        let existing = self.existing_node_for_path(top, &path)?;

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the bottom node.
        let mut current_hash = Node::hash_leaf(self.hasher.clone(), item);
        for (side, neighbor) in path.iter().take(existing.level) {
            let (l, r) = side.order(&current_hash, neighbor);
            current_hash = Node::hash_intermediate(self.hasher.clone(), l, r);
        }

        // 5. Check if we arrived at a correct lowest-available node.
        if current_hash != existing.hash {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidMerkleProof);
        }

        Ok(())
    }

    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert<M: MerkleItem>(&mut self, item: &M) -> Proof {
        // Same position for new items since we look them up by hash.
        // After check point, we'll still look them up by hash.
        // At the same time, position after the pre-existing nodes indicates
        // that this item is an insertion.
        let hash = Node::hash_leaf(self.hasher.clone(), item);
        self.insertions.insert(hash, ());

        Proof {
            generation: self.generation,
            path: None,
        }
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    ///
    /// The algorithm minimizes amount of computation by taking advantage of the already available data.
    ///
    /// Consider the following partially filled tree due to previous operations:
    ///
    /// ```ascii
    /// A         level 4
    /// | \
    /// B  C      level 3
    ///    | \
    ///    D  E   level 2
    /// ```
    ///
    /// Then, an item H is deleted at absolute position 10, with a merkle proof `J',F',E',B'`:
    ///
    /// ```ascii
    /// A         
    /// | \
    /// B  C   
    ///    | \
    ///    D  E   
    ///    | \
    ///    F  G
    ///       | \
    ///      (H) J
    /// ```
    ///
    /// First, we walk the existing tree down to the smallest
    /// available subtree that supposedly contains our item:
    /// in this case it's the node `D`.
    ///
    /// Then, we walk the merkle proof up to node `D`:
    ///
    /// ```ascii
    /// hash(H',J') -> G'
    /// hash(F',G') -> D'
    /// ```
    ///
    /// If D' is not equal to D, reject the proof.
    /// Otherwise, continue walking up the tree to the actual root (A),
    /// but instead of hashing, simply compare remaining steps in the proof with the stored nodes:
    ///
    /// ```ascii
    /// E' == E
    /// B' == B
    /// ```
    ///
    /// Note: the remaining equality checks are necessary to make sure the proof is fully valid for relay
    /// to other nodes, but not necessary to verify the inclusion of the item H (which is proven by
    /// inclusion into D already).
    ///
    pub fn delete<M: MerkleItem>(&mut self, item: &M, proof: &Proof) -> Result<(), UtreexoError> {
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
                let hash = Node::hash_leaf(self.hasher.clone(), item);
                return self
                    .insertions
                    .remove(&hash)
                    .ok_or(UtreexoError::InvalidMerkleProof);
            }
        };

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let top = self.root_containing_position(path.position)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != top.level {
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        //    And also check the higher-level neighbors in the proof.
        let existing = self.existing_node_for_path(top, &path)?;

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the bottom node.
        // TBD: reuse preallocated scratch-space?
        let mut new_heap = self.heap.make_extension(2 * existing.level);
        let mut current_hash = Node::hash_leaf(self.hasher.clone(), item);
        let mut current_children = existing.children;
        for (i, (side, neighbor)) in path.iter().enumerate().take(existing.level) {
            let current = new_heap.allocate_node(|node| {
                node.hash = current_hash;
                node.level = i;
            });
            let sibling = new_heap.allocate_node(|node| {
                node.hash = *neighbor;
                node.level = i;
            });
            // reordering of current/sibling is done only for hashing.
            // we guarantee that the current node is always going before the sibling on the heap,
            // to have stable parent index (parent is always stored before _its_ sibling).
            let (l, r) = side.order(&current, &sibling);

            current_hash = Node::hash_intermediate(self.hasher.clone(), &l.hash, &r.hash);
            current_children = Some((l.index, r.index));
        }

        // 5. Check if we arrived at a correct lowest-available node.
        if current_hash != existing.hash {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // All checks succeeded: we can now attach new nodes and
        // update the deletions count up to the root.

        // Before we update the heap, get the correct index of the deleted leaf node.
        let leaf_index: NodeIndex = if existing.level == 0 {
            existing.index
        } else {
            // if the lower level was not the leaf, the first new node is the leaf node.
            self.heap.next_index()
        };

        // Move newly created nodes into the main heap
        self.heap.extend(new_heap);

        // Connect children to the existing lower node.
        let _ = self
            .heap
            .update_node_at(existing.index, |node| node.children = current_children);

        // Update modification flag for all parents of the deleted leaf.
        let _ = path.iter().try_fold(leaf_index, |index, (side, _)| {
            self.heap
                .update_node_at(index, |node| node.modified = true)
                .children
                .map(|(l, r)| side.choose(l, r))
        });

        self.deletions += 1;

        Ok(())
    }

    /// Normalizes the forest into minimal number of ordered perfect trees.
    /// Returns a root of the new forst, the forest and a catchup structure.
    pub fn normalize(self) -> (Hash, Forest, Catchup) {
        // 1. Relocate all perfect subtrees (w/o deletions) into a new forest.
        // 2. Scan levels from 0 to max level, connecting pairs of the closest same-level nodes.
        // 3. Reorder trees into canonical order, from high to low level.
        // 4. Traverse the entire tree creating Catchup entries for the nodes w/o children.
        // 5. Extract a thinner Forest structure to return separately,
        //    so it can be kept while Catchup can be optionally discarded.

        // TBD: what's the best way to estimate the vector capacity from self.heap.len()?
        let estimated_cap = self.heap.len() / 2 + self.insertions.len();
        let mut new_heap = Heap::with_capacity(estimated_cap);
        let mut new_trees = Vec::<NodeIndex>::with_capacity(estimated_cap);

        // Collect all nodes that were not modified.
        // 1) add pre-existing unmodified nodes...
        for root in self.roots_iter() {
            self.heap.traverse(0, root, &mut |_, node: &Node| {
                if node.modified {
                    true // traverse into children until we find unmodified nodes
                } else {
                    // non-modified node - collect and ignore children
                    new_trees.push(
                        new_heap
                            .allocate_node(|n| {
                                n.hash = node.hash;
                                n.level = node.level;
                            })
                            .index,
                    );
                    false
                }
            })
        }

        // 2) ...and newly inserted nodes.
        for (hash, _) in self.insertions.into_iter() {
            new_trees.push(
                new_heap
                    .allocate_node(|n| {
                        n.hash = hash;
                        n.level = 0;
                    })
                    .index,
            );
        }

        // we just consumed `self.insertions`, so let's also move out the hasher.
        let hasher = self.hasher;

        // Compute perfect roots for the new tree,
        // joining together same-level nodes into higher-level nodes.
        let new_roots = {
            let mut new_roots = [None as Option<NodeIndex>; 64];

            // The `left` variable will flip-flop between None and Some as we match pairs of nodes.
            let mut left: Option<(usize, Node)> = None;

            // Scan each level, from low to high, and match up available pairs of nodes, moving
            // the right node closer to the left node.
            for level in 0..64 {
                let mut i = 0;
                while i < new_trees.len() {
                    let node = new_heap.node_at(new_trees[i]);
                    if node.level != level {
                        // skip nodes at other levels
                        i += 1;
                        continue;
                    }
                    if let Some((prev_i, l)) = left {
                        // Remove the right node
                        let r = new_heap.node_at(new_trees.remove(i));
                        let p = new_heap.allocate_node(|node| {
                            node.hash = Node::hash_intermediate(hasher.clone(), &l.hash, &r.hash);
                            node.level = level + 1;
                            node.children = Some((l.index, r.index))
                        });

                        // Replace left child index with the new parent.
                        new_trees[prev_i] = p.index;

                        // Forget the left item as we have successfully matched it up with the right node.
                        left = None;

                        // Clear the remembered level for the left item that we just consumed.
                        // The parent will be remembered in the loop for the level+1.
                        new_roots[level] = None;

                    // Do not increment `i` since we just removed that item from the list
                    // and the current value of `i` now points to the next item (or the end).
                    } else {
                        // Remember the first node in the pair
                        left = Some((i, node));

                        // Remember this node's index for this level.
                        new_roots[level] = Some(node.index);
                        i += 1;
                    }
                }
                // if there was no matching right node, leave the left one in the tree,
                // forgetting it before we go to the higher level.
                left = None;
            }
            new_roots
        };

        let new_forest = Forest {
            generation: self.generation + 1,
            roots: new_roots,
            insertions: HashMap::new(), // will remain empty
            deletions: 0,
            heap: new_heap,
            hasher: hasher.clone(),
        };

        // Create a new, trimmed forest.
        let trimmed_forest = new_forest.trim();
        let catchup = new_forest.into_catchup();
        let top_root = trimmed_forest.compute_root();

        (top_root, trimmed_forest, catchup)
    }

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
        Err(UtreexoError::ItemOutOfBounds)
    }

    /// Returns the lowest-available node for a given path and verifies the higher-level
    /// neighbors in the path.
    fn existing_node_for_path(&self, root: Node, path: &Path) -> Result<Node, UtreexoError> {
        let existing: Node = path
            .iter()
            .rev()
            .try_fold(
                (root, root.children),
                |(node, children), (side, proof_neighbor)| {
                    if let Some((li, ri)) = children {
                        let actual_neighor = self.heap.hash_at(side.choose(ri, li));
                        if proof_neighbor != &actual_neighor {
                            return Err(UtreexoError::InvalidMerkleProof);
                        }
                        let next_node = self.heap.node_at(side.choose(li, ri));
                        Ok((next_node, next_node.children))
                    } else {
                        // keep the node we found till the end of the iteration
                        Ok((node, None))
                    }
                },
            )?
            .0;

        Ok(existing)
    }

    /// Returns an iterator over roots of the forest,
    /// from the highest to the lowest level.
    fn roots_iter<'a>(&'a self) -> impl DoubleEndedIterator<Item = Node> + 'a {
        self.roots
            .iter()
            .rev()
            .filter_map(move |optional_index| optional_index.map(|index| self.heap.node_at(index)))
    }

    /// Trims the forest leaving only the root nodes.
    /// Assumes the forest is normalized.
    fn trim(&self) -> Forest {
        let mut trimmed_forest = Forest {
            generation: self.generation,
            roots: [None; 64],          // filled in below
            insertions: HashMap::new(), // will remain empty
            deletions: 0,
            heap: Heap::with_capacity(64), // filled in below
            hasher: self.hasher.clone(),
        };
        // copy the roots from the new forest to the trimmed forest
        for root in self.roots_iter() {
            let trimmed_root = trimmed_forest.heap.allocate_node(|node| {
                node.hash = root.hash;
                node.level = root.level;
            });
            trimmed_forest.roots[trimmed_root.level] = Some(trimmed_root.index);
        }
        trimmed_forest
    }

    /// Wraps the forest into a Catchup structure
    fn into_catchup(self) -> Catchup {
        // Traverse the tree to collect the catchup entries
        let mut catchup_map: HashMap<Hash, Position> = HashMap::new();
        let mut top_offset: Position = 0;
        for root in self.roots_iter() {
            top_offset += root.capacity();

            // collect nodes without children into the Catchup map
            self.heap
                .traverse(top_offset, root, &mut |offset, node: &Node| {
                    if node.children == None {
                        catchup_map.insert(node.hash, offset);
                    }
                    true
                });
        }
        Catchup {
            forest: self,
            map: catchup_map,
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
                    Some(Node::hash_intermediate(self.hasher.clone(), &node.hash, &h))
                } else {
                    // this is the first iteration - use node's hash as-is
                    Some(node.hash)
                }
            })
            .unwrap_or(Node::hash_empty(self.hasher.clone()))
    }
}

impl Catchup {
    /// Updates the proof if it's slightly out of date
    /// (made against the previous generation of the Utreexo).
    pub fn update_proof<M: MerkleItem>(
        &self,
        item: &M,
        proof: Proof,
    ) -> Result<Proof, UtreexoError> {
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

        let hash = Node::hash_leaf(self.forest.hasher.clone(), item);

        // Climb up the merkle path until we find an existing node or nothing.
        let (level, catchup_result, _) = path.iter().fold(
            (0, self.map.get(&hash), hash),
            |(level, catchup_result, hash), (side, neighbor)| match catchup_result {
                Some(r) => (level, Some(r), hash),
                None => {
                    let (l, r) = side.order(&hash, neighbor);
                    let hash = Node::hash_intermediate(self.forest.hasher.clone(), &l, &r);
                    let catchup_result = self.map.get(&hash);
                    (level + 1, catchup_result, hash)
                }
            },
        );

        // Fail early if we did not find any catchup point.
        let position_offset = catchup_result.ok_or(UtreexoError::InvalidMerkleProof)?;

        // Adjust the absolute position:
        // keep the lowest (level+1) bits and add the stored position offset for the stored subtree
        let mask: Position = (1 << level) - 1; // L=0 -> ...00, L=1 -> ...01, L=2 -> ...11
        path.position = position_offset + (path.position & mask);

        // Remove all outdated neighbors
        path.neighbors.truncate(level);

        // Find the root to which the updated position belongs
        let root = self.forest.root_containing_position(path.position)?;

        path.neighbors = path
            .side_iter(root.level)
            .rev()
            .take(root.level - level)
            .try_fold((root, path.neighbors), |(node, mut neighbors), side| {
                let (li, ri) = node.children.ok_or(UtreexoError::InternalInconsistency)?;
                let new_neighbor = self.forest.heap.hash_at(side.choose(ri, li));
                let lower_node = self.forest.heap.node_at(side.choose(li, ri));
                // FIXME: suboptimal, but correct - the higher-level nodes are shifted to the end
                // The faster way is to fill the missing places with zeroes first,
                // then insert in-place from end towards the beginning.
                neighbors.insert(level, new_neighbor);
                Ok((lower_node, neighbors))
            })?
            .1;

        Ok(Proof {
            generation: self.forest.generation,
            path: Some(path),
        })
    }
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum Side {
    Left,
    Right,
}

impl Side {
    /// Orders a node and its neighbor according to the node's side.
    /// If self == Left, returns (node, neighbor) and the reverse otherwise.
    fn order<T>(self, node: T, neighbor: T) -> (T, T) {
        match self {
            Side::Left => (node, neighbor),
            Side::Right => (neighbor, node),
        }
    }

    fn choose<T>(self, left: T, right: T) -> T {
        match self {
            Side::Left => left,
            Side::Right => right,
        }
    }

    fn from_bit(bit: u8) -> Self {
        if bit == 0 {
            Side::Left
        } else {
            Side::Right
        }
    }
}

impl Path {
    fn iter(&self) -> impl DoubleEndedIterator<Item = (Side, &Hash)> + ExactSizeIterator {
        self.side_iter(self.neighbors.len())
            .zip(self.neighbors.iter())
    }
    fn side_iter(
        &self,
        length: usize,
    ) -> impl DoubleEndedIterator<Item = Side> + ExactSizeIterator {
        PathIterator {
            start: 0,
            end: length,
            position: self.position,
        }
    }
}

struct PathIterator {
    start: usize,
    end: usize,
    position: Position,
}

impl ExactSizeIterator for PathIterator {
    fn len(&self) -> usize {
        self.end - self.start
    }
}

impl Iterator for PathIterator {
    type Item = Side;
    fn next(&mut self) -> Option<Self::Item> {
        if self.start == self.end {
            return None;
        }
        let i = self.start;
        let side = Side::from_bit(((self.position >> i) & 1) as u8);
        self.start += 1;
        Some(side)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

impl DoubleEndedIterator for PathIterator {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.start == self.end {
            return None;
        }
        self.end -= 1;
        let i = self.end;
        let side = Side::from_bit(((self.position >> i) & 1) as u8);
        Some(side)
    }
}

impl Heap {
    fn new() -> Heap {
        Heap {
            offset: 0,
            heap: Vec::new(),
        }
    }

    fn with_capacity(cap: usize) -> Self {
        Heap {
            offset: 0,
            heap: Vec::with_capacity(cap),
        }
    }

    fn next_index(&self) -> NodeIndex {
        self.offset + (self.heap.len() as NodeIndex)
    }

    fn make_extension(&self, capacity: usize) -> Self {
        Heap {
            offset: self.next_index(),
            heap: Vec::with_capacity(capacity),
        }
    }

    fn extend(&mut self, extension: Heap) {
        // make sure the extension Heap is contiguous with this Heap
        debug_assert!(extension.offset == self.next_index());
        self.heap.extend(extension.heap);
    }

    /// Allocates a perfect tree in the heap. Guarantees that the node index will be
    /// equal to `self.next_index()` before the allocation,
    /// and the `self.next_index()` is going to be incremented after the allocation.
    fn allocate_node(&mut self, closure: impl FnOnce(&mut Node)) -> Node {
        let mut node = Node {
            hash: [0u8; 32],
            index: self.next_index(),
            level: 0,
            modified: false,
            children: None, // trim children
        };
        closure(&mut node);
        self.heap.push(node.pack());
        node
    }

    fn update_node_at(&mut self, i: NodeIndex, closure: impl FnOnce(&mut Node)) -> Node {
        let storage_index = self.storage_index(i);
        let mut node = self.heap[storage_index].unpack(i);
        closure(&mut node);
        self.heap[storage_index] = node.pack();
        node
    }

    fn node_at(&self, i: NodeIndex) -> Node {
        self.heap[self.storage_index(i)].unpack(i)
    }

    fn hash_at(&self, i: NodeIndex) -> Hash {
        self.heap[self.storage_index(i)].hash
    }

    fn storage_index(&self, i: NodeIndex) -> usize {
        (i - self.offset)
    }

    fn len(&self) -> usize {
        self.heap.len()
    }

    /// Traverses all nodes in a tree starting with a given node.
    /// If the callback `f` returns `false` for some node,
    /// does not recurse into the node's children.
    fn traverse(&self, offset: Position, node: Node, f: &mut impl FnMut(Position, &Node) -> bool) {
        if f(offset, &node) {
            if let Some((li, ri)) = node.children {
                let (l, r) = (self.node_at(li), self.node_at(ri));
                self.traverse(offset, l, f);
                self.traverse(offset + l.capacity(), r, f);
            }
        }
    }
}

impl Node {
    /// maximum number of items in this subtree, ignoring deletions
    fn capacity(&self) -> u64 {
        1 << self.level
    }

    fn hash_leaf<M: MerkleItem>(mut h: NodeHasher, item: &M) -> Hash {
        item.commit(&mut h.transcript);
        let mut hash = [0; 32];
        h.transcript.challenge_bytes(b"merkle.leaf", &mut hash);
        hash
    }

    fn hash_intermediate(mut h: NodeHasher, left: &Hash, right: &Hash) -> Hash {
        h.transcript.commit_bytes(b"L", left);
        h.transcript.commit_bytes(b"R", right);
        let mut hash = [0; 32];
        h.transcript.challenge_bytes(b"merkle.node", &mut hash);
        hash
    }

    fn hash_empty(mut h: NodeHasher) -> Hash {
        let mut hash = [0; 32];
        h.transcript.challenge_bytes(b"merkle.empty", &mut hash);
        hash
    }

    fn pack(&self) -> PackedNode {
        debug_assert!(self.level < 64);

        let modflag = if self.modified { 64 } else { 0 };

        let (chflag, (l, r)) = self
            .children
            .map(|(l, r)| {
                let l = l as u32;
                let r = r as u32;
                (128, (l, r))
            })
            .unwrap_or((0, (0xffffffff, 0xffffffff)));

        PackedNode {
            hash: self.hash,
            flags: (self.level as u8) + modflag + chflag,
            children: (l, r),
        }
    }
}

impl PackedNode {
    fn validate_index(index: usize) -> Result<(), UtreexoError> {
        if index >= 0xffffffff {
            return Err(UtreexoError::ExceedingCapacity);
        }
        Ok(())
    }
    fn unpack(&self, index: NodeIndex) -> Node {
        Node {
            hash: self.hash,
            index,
            level: (self.flags & 63) as usize,
            modified: (self.flags & 64) == 64,
            children: if self.flags & 128 == 0 {
                None
            } else {
                Some((self.children.0 as NodeIndex, self.children.1 as NodeIndex))
            },
        }
    }
}

impl NodeHasher {
    /// Creates a hasher
    fn new() -> Self {
        Self {
            transcript: Transcript::new(b"ZkVM.utreexo"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::*;

    impl MerkleItem for u64 {
        fn commit(&self, t: &mut Transcript) {
            t.commit_u64(b"test_item", *self);
        }
    }

    impl Into<H> for u64 {
        fn into(self) -> H {
            let mut t = Transcript::new(b"ZkVM.utreexo");
            self.commit(&mut t);
            let mut hash = [0; 32];
            t.challenge_bytes(b"merkle.leaf", &mut hash);
            H(hash)
        }
    }

    impl Into<H> for Hash {
        fn into(self) -> H {
            H(self)
        }
    }

    struct H(Hash); // wrapper to overcome trait orphan rules

    fn h<L: Into<H>, R: Into<H>>(l: L, r: R) -> Hash {
        let mut t = Transcript::new(b"ZkVM.utreexo");
        t.commit_bytes(b"L", &l.into().0);
        t.commit_bytes(b"R", &r.into().0);
        let mut hash = [0; 32];
        t.challenge_bytes(b"merkle.node", &mut hash);
        hash
    }

    #[test]
    fn empty_utreexo() {
        let forest0 = Forest::new();
        let metrics0 = forest0.metrics();
        assert_eq!(metrics0.generation, 0);
        assert_eq!(metrics0.count, 0);
        assert_eq!(metrics0.insertions, 0);
        assert_eq!(metrics0.deletions, 0);

        let (root0, forest1, _catchup1) = forest0.normalize();
        let metrics1 = forest1.metrics();
        assert_eq!(root0, MerkleTree::root::<u64>(b"ZkVM.utreexo", &[]));
        assert_eq!(metrics1.generation, 1);
        assert_eq!(metrics1.count, 0);
        assert_eq!(metrics1.insertions, 0);
        assert_eq!(metrics1.deletions, 0);
    }

    #[test]
    fn transient_items_utreexo() {
        let mut forest0 = Forest::new();

        let proof0 = forest0.insert(&0);
        let proof1 = forest0.insert(&1);

        assert_eq!(
            forest0.metrics(),
            Metrics {
                generation: 0,
                count: 2,
                insertions: 2,
                deletions: 0,
            }
        );

        forest0.delete(&1, &proof1).unwrap();
        forest0.delete(&0, &proof0).unwrap();

        assert_eq!(
            forest0.metrics(),
            Metrics {
                generation: 0,
                count: 0,
                insertions: 0,
                deletions: 0,
            }
        );
    }
}
