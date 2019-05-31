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
use core::mem;
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
#[derive(Clone, Debug)]
pub struct Proof {
    /// Generation of the forest to which the proof applies.
    pub generation: u64,

    /// Merkle path to the item. If missing, the proof applies to a yet-to-be-normalized forest.
    pub path: Option<Path>,
}

/// Merkle path to the item.
#[derive(Clone, Debug)]
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
    insertions: Vec<Hash>, // new items (TBD: maybe use a fancy order-preserving HashSet later)
    deletions: usize,
    heap: Heap,
    hasher: Transcript,
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

    /// Lower-bound for amount of memory occupied in bytes.
    pub memory: usize,
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
            insertions: Vec::new(),
            deletions: 0,
            heap: Heap::new(),
            hasher: Transcript::new(b"ZkVM.utreexo"),
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
            memory: mem::size_of::<Self>()
                + mem::size_of::<Hash>() * self.insertions.len()
                + mem::size_of::<Heap>()
                + self.heap.storage.len() * mem::size_of::<PackedNode>(),
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
                    .iter()
                    .find(|&h| h == &hash)
                    .map(|_| ())
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
        let current_hash = Node::hash_leaf(self.hasher.clone(), item);
        let current_hash = path
            .walk_up(current_hash, &self.hasher)
            .take(existing.level)
            .fold(current_hash, |_, (parent, _)| parent);

        // 5. Check if we arrived at a correct lowest-available node.
        if current_hash != existing.hash {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidMerkleProof);
        }

        Ok(())
    }

    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert<M: MerkleItem>(&mut self, item: &M) -> Proof {
        let hash = Node::hash_leaf(self.hasher.clone(), item);
        self.insertions.push(hash);
        Proof {
            generation: self.generation,
            path: None,
        }
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    ///
    /// The algorithm minimizes amount of computation by taking advantage of the already available data.
    ///
    /// Consider the following partially filled tree due to previous updates:
    ///
    /// ```ascii
    /// A         level 4
    /// | \
    /// B  C      level 3
    ///    | \
    ///    D  E   level 2
    /// ```
    ///
    /// Then, an item (H) is deleted at absolute position 10, with a merkle proof `J',F',E',B'`:
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
    /// As we do that, we verify the corresponding neighbors in the merkle proof
    /// by simple equality check (these must match the nodes already present in the tree).
    ///
    /// Then, we walk the merkle proof up to node `D` computing the missing hashes:
    ///
    /// ```ascii
    /// hash(H',J') -> G'
    /// hash(F',G') -> D'
    /// ```
    ///
    /// If D' is not equal to D, reject the proof.
    ///
    /// If the proof is valid, connect the newly created nodes (D',F,G,H,J) to the tree
    /// and mark all intermediate nodes on the path from (H) to the root A as modified.
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
                let index = self
                    .insertions
                    .iter()
                    .enumerate()
                    .find(|&(_, h)| h == &hash)
                    .map(|(i, _)| i)
                    .ok_or(UtreexoError::InvalidMerkleProof)?;
                self.insertions.remove(index);
                return Ok(());
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
        let hasher = self.hasher.clone();
        let new_children = self.heap.transaction(|mut heap| {
            let item_hash = Node::hash_leaf(hasher.clone(), item);

            let (hash, children) = path
                .directions()
                .zip(path.walk_up(item_hash, &hasher))
                .enumerate()
                .take(existing.level)
                .fold(
                    (item_hash, None),
                    |(_, children), (i, (side, (parent_hash, (left_hash, right_hash))))| {
                        let (left_children, right_children) = side.to_left_right(children, None);
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
                return Err(UtreexoError::InvalidMerkleProof);
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
                self.heap.update(side.choose(l, r), |node| {
                    node.modified = true;
                })
            })
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
                    let new_node = new_heap.allocate(node.hash, node.level, None);
                    new_trees.push(new_node.index);
                    false
                }
            })
        }

        // 2) ...and newly inserted nodes.
        for hash in self.insertions.into_iter() {
            let new_node = new_heap.allocate(hash, 0, None);
            new_trees.push(new_node.index);
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
                        let p = new_heap.allocate(
                            Node::hash_intermediate(hasher.clone(), &l.hash, &r.hash),
                            level + 1,
                            Some((l.index, r.index)),
                        );

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
            insertions: Vec::new(), // will remain empty
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

        // Climb up the merkle path until we find an existing node or nothing.
        let hash = Node::hash_leaf(self.forest.hasher.clone(), item);
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
        let position_offset = catchup_result.ok_or(UtreexoError::InvalidMerkleProof)?;

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
            |mut list, (_, new_neighbor)| {
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

// Private implementation

impl Forest {
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
        self.heap
            .walk_down(root, path.directions().rev())
            .zip(path.neighbors.iter().rev())
            .try_fold(root, |_, ((node, actual_neighbor), proof_neighbor)| {
                if proof_neighbor != &actual_neighbor.hash {
                    Err(UtreexoError::InvalidMerkleProof)
                } else {
                    Ok(node)
                }
            })
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
            roots: [None; 64],      // filled in below
            insertions: Vec::new(), // will remain empty
            deletions: 0,
            heap: Heap::with_capacity(64), // filled in below
            hasher: self.hasher.clone(),
        };
        // copy the roots from the new forest to the trimmed forest
        for root in self.roots_iter() {
            let trimmed_root = trimmed_forest.heap.allocate(root.hash, root.level, None);
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
            // collect nodes without children into the Catchup map
            self.heap
                .traverse(top_offset, root, &mut |offset, node: &Node| {
                    if node.children == None {
                        catchup_map.insert(node.hash, offset);
                    }
                    true
                });
            top_offset += root.capacity();
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
#[repr(packed)]
struct PackedNode {
    hash: Hash,
    flags: u8,
    children: (u32, u32),
}

/// Simialr to Path, but does not contain neighbors - only left/right directions
/// as indicated by the bits in the `position`.
#[derive(Copy, Clone, PartialEq, Debug)]
struct Directions {
    position: Position,
    depth: usize,
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum Side {
    Left,
    Right,
}

impl Side {
    /// Orders a node and its neighbor according to the node's side.
    /// If self == Left, returns (node, neighbor) and the reverse otherwise.
    fn to_left_right<T>(self, node: T, neighbor: T) -> (T, T) {
        match self {
            Side::Left => (node, neighbor),
            Side::Right => (neighbor, node),
        }
    }

    /// Returns pair of ("current" node, "neighbor" node) based on the side.
    /// This is the reverse of `to_left_right`.
    fn from_left_right<T>(self, left: T, right: T) -> (T, T) {
        match self {
            Side::Left => (left, right),
            Side::Right => (right, left),
        }
    }

    /// Chooses between left or right, according to the side.
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
        self.directions().zip(self.neighbors.iter())
    }
    fn directions(&self) -> Directions {
        Directions {
            position: self.position,
            depth: self.neighbors.len(),
        }
    }
    /// Returns an iterator that walks up the path
    /// and yields parent hash and children hashes at each step.
    fn walk_up<'a, 'b: 'a>(
        &'a self,
        item_hash: Hash,
        hasher: &'b Transcript,
    ) -> impl Iterator<Item = (Hash, (Hash, Hash))> + 'a {
        self.iter()
            .scan(item_hash, move |item_hash, (side, neighbor)| {
                let (l, r) = side.to_left_right(*item_hash, *neighbor);
                let p = Node::hash_intermediate(hasher.clone(), &l, &r);
                *item_hash = p;
                Some((p, (l, r)))
            })
    }
}

impl ExactSizeIterator for Directions {
    fn len(&self) -> usize {
        self.depth
    }
}

impl Iterator for Directions {
    type Item = Side;
    fn next(&mut self) -> Option<Self::Item> {
        if self.depth == 0 {
            return None;
        }
        let side = Side::from_bit((self.position & 1) as u8);
        // kick out the lowest bit and shrink the depth
        self.position >>= 1;
        self.depth -= 1;
        Some(side)
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len(), Some(self.len()))
    }
}

impl DoubleEndedIterator for Directions {
    fn next_back(&mut self) -> Option<Self::Item> {
        if self.depth == 0 {
            return None;
        }
        self.depth -= 1;
        // Note: we do not mask out the bit in `position` because we don't expose it.
        // The bit is ignored implicitly by having the depth decremented.
        let side = Side::from_bit(((self.position >> self.depth) & 1) as u8);
        Some(side)
    }
}

/// Storage of all the nodes with methods to access them.
#[derive(Clone)]
struct Heap {
    storage: Vec<PackedNode>,
}

struct HeapAllocOnly<'a> {
    heap: &'a mut Heap,
}

impl<'a> HeapAllocOnly<'a> {
    fn allocate(
        &mut self,
        hash: Hash,
        level: usize,
        children: Option<(NodeIndex, NodeIndex)>,
    ) -> Node {
        self.heap.allocate(hash, level, children)
    }
}

impl Heap {
    fn new() -> Heap {
        Heap {
            storage: Vec::new(),
        }
    }

    fn with_capacity(cap: usize) -> Self {
        Heap {
            storage: Vec::with_capacity(cap),
        }
    }

    fn node_at(&self, i: NodeIndex) -> Node {
        self.storage[i].unpack(i)
    }

    fn len(&self) -> usize {
        self.storage.len()
    }

    /// Perform allocations in a transaction block: all allocations are removed
    /// if the block fails.
    fn transaction<T, E>(
        &mut self,
        closure: impl FnOnce(HeapAllocOnly) -> Result<T, E>,
    ) -> Result<T, E> {
        let pre_transaction_size = self.storage.len();
        match closure(HeapAllocOnly { heap: self }) {
            Ok(x) => Ok(x),
            Err(e) => {
                // undo all newly allocated items, but keep the allocated capacity for future use
                self.storage.truncate(pre_transaction_size);
                Err(e)
            }
        }
    }

    /// Allocates a node in the heap.
    fn allocate(
        &mut self,
        hash: Hash,
        level: usize,
        children: Option<(NodeIndex, NodeIndex)>,
    ) -> Node {
        // make sure our indices fit in 32 bits.
        assert!(self.storage.len() <= 0xffffffff);
        let node = Node {
            hash,
            index: self.storage.len() as NodeIndex,
            level,
            modified: false,
            children,
        };
        self.storage.push(node.pack());
        node
    }

    fn update(&mut self, i: NodeIndex, closure: impl FnOnce(&mut Node)) -> Node {
        let mut node = self.node_at(i);
        closure(&mut node);
        self.storage[i] = node.pack();
        node
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

    /// Returns an iterator that walks the given path (from root down)
    /// and yields current node and its neighbor.
    /// * Root node is NOT included.
    /// * The last node yielded by the iterator is the node without children.
    /// * If the root has no children, iterator yields None on the first iteration.
    fn walk_down<'a, 'b: 'a>(
        &'a self,
        root: Node,
        directions: impl Iterator<Item = Side> + 'b,
    ) -> impl Iterator<Item = (Node, Node)> + '_ {
        directions.scan(root.children, move |children, side| {
            children.map(|(li, ri)| {
                let (main, neighbor) = side.from_left_right(self.node_at(li), self.node_at(ri));
                *children = main.children;
                (main, neighbor)
            })
        })
    }
}

impl Node {
    /// maximum number of items in this subtree, ignoring deletions
    fn capacity(&self) -> u64 {
        1 << self.level
    }

    fn hash_leaf<M: MerkleItem>(mut h: Transcript, item: &M) -> Hash {
        item.commit(&mut h);
        let mut hash = [0; 32];
        h.challenge_bytes(b"merkle.leaf", &mut hash);
        hash
    }

    fn hash_intermediate(mut h: Transcript, left: &Hash, right: &Hash) -> Hash {
        h.commit_bytes(b"L", left);
        h.commit_bytes(b"R", right);
        let mut hash = [0; 32];
        h.challenge_bytes(b"merkle.node", &mut hash);
        hash
    }

    fn hash_empty(mut h: Transcript) -> Hash {
        let mut hash = [0; 32];
        h.challenge_bytes(b"merkle.empty", &mut hash);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::*;

    impl MerkleItem for u64 {
        fn commit(&self, t: &mut Transcript) {
            t.commit_u64(b"test_item", *self);
        }
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
                memory: forest0.metrics().memory,
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
                memory: forest0.metrics().memory,
            }
        );
    }

    #[test]
    fn insert_to_utreexo() {
        let mut forest0 = Forest::new();

        let proofs0 = (0..6).map(|i| forest0.insert(&i)).collect::<Vec<_>>();

        let (root, mut forest1, catchup1) = forest0.normalize();

        assert_eq!(
            forest1.metrics(),
            Metrics {
                generation: 1,
                count: 6,
                insertions: 0,
                deletions: 0,
                memory: forest1.metrics().memory,
            }
        );

        assert_eq!(
            root,
            MerkleTree::root::<u64>(b"ZkVM.utreexo", &(0..6).collect::<Vec<_>>())
        );

        for i in 0..6u64 {
            let deletion = forest1.delete(&i, &proofs0[i as usize]);
            assert_eq!(deletion, Err(UtreexoError::OutdatedProof));
        }

        // update the proofs
        let proofs1 = proofs0
            .into_iter()
            .enumerate()
            .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
            .collect::<Vec<_>>();

        // after the proofs were updated, deletions should succeed
        for i in 0..6u64 {
            forest1.delete(&i, &proofs1[i as usize]).unwrap();
        }

        assert_eq!(
            forest1.metrics(),
            Metrics {
                generation: 1,
                count: 0,
                insertions: 0,
                deletions: 6,
                memory: forest1.metrics().memory,
            }
        );
    }

    #[test]
    fn insert_and_delete_utreexo() {
        let mut forest0 = Forest::new();
        let n = 6u64;
        let proofs0 = (0..n).map(|i| forest0.insert(&i)).collect::<Vec<_>>();

        let (_, forest1, catchup1) = forest0.normalize();

        assert_eq!(
            forest1.metrics(),
            Metrics {
                generation: 1,
                count: n as usize,
                insertions: 0,
                deletions: 0,
                memory: forest1.metrics().memory,
            }
        );

        // update the proofs
        let proofs1 = proofs0
            .into_iter()
            .enumerate()
            .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
            .collect::<Vec<_>>();

        // after the proofs were updated, deletions should succeed

        {
            /* delete 0:
                d                                       e
                |\                                      | \
                a   b   c      ->        b   c      ->  b   c
                |\  |\  |\               |\  |\         |\  |\
                0 1 2 3 4 5          x 1 2 3 4 5        2 3 4 5 1
            */
            let mut forest = forest1.clone();
            forest.verify(&0u64, &proofs1[0]).unwrap();
            forest.delete(&0u64, &proofs1[0]).unwrap();

            let (root, _, _) = forest.normalize();
            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2u64, 3, 4, 5, 1])
            )
        }

        {
            /* delete 1:
                d                                       e
                |\                                      | \
                a   b   c      ->        b   c      ->  b   c
                |\  |\  |\               |\  |\         |\  |\
                0 1 2 3 4 5          0 x 2 3 4 5        2 3 4 5 0
            */
            let mut forest = forest1.clone();
            forest.verify(&1u64, &proofs1[1]).unwrap();
            forest.delete(&1u64, &proofs1[1]).unwrap();

            let (root, _, _) = forest.normalize();
            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2u64, 3, 4, 5, 0])
            )
        }

        {
            /* delete 2:
                d                                       e
                |\                                      | \
                a   b   c      ->    a       c      ->  a   c
                |\  |\  |\           |\      |\         |\  |\
                0 1 2 3 4 5          0 1 x 3 4 5        0 1 4 5 3
            */
            let mut forest = forest1.clone();
            forest.delete(&2u64, &proofs1[2]).unwrap();

            let (root, _, _) = forest.normalize();
            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0u64, 1, 4, 5, 3])
            )
        }

        {
            /* delete 5:
                d                                       e
                |\                                      | \
                a   b   c      ->    a   b          ->  a   b
                |\  |\  |\           |\  |\             |\  |\
                0 1 2 3 4 5          0 1 2 3 4 x        0 1 2 3 4
            */
            let mut forest = forest1.clone();
            forest.delete(&5u64, &proofs1[5]).unwrap();

            let (root, _, _) = forest.normalize();
            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0u64, 1, 2, 3, 4])
            )
        }

        {
            /* delete 2,3:
                d                                       e
                |\                                      | \
                a   b   c      ->    a       c      ->  a   c
                |\  |\  |\           |\      |\         |\  |\
                0 1 2 3 4 5          0 1 x x 4 5        0 1 4 5
            */
            let mut forest = forest1.clone();
            forest.delete(&2u64, &proofs1[2]).unwrap();
            forest.delete(&3u64, &proofs1[3]).unwrap();

            let (root, _, _) = forest.normalize();
            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0u64, 1, 4, 5])
            );

            let mut forest_b = forest1.clone(); // try deletion in another order
            forest_b.delete(&3u64, &proofs1[3]).unwrap();
            forest_b.delete(&2u64, &proofs1[2]).unwrap();

            let (root, _, _) = forest_b.normalize();
            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[0u64, 1, 4, 5])
            );
        }

        {
            /* delete 0,3:
                d                                       f
                |\                                      | \
                a   b   c      ->            c      ->  e   c
                |\  |\  |\                   |\         |\  |\
                0 1 2 3 4 5          x 1 2 x 4 5        1 2 4 5
            */
            let mut forest = forest1.clone();
            forest.verify(&0u64, &proofs1[0]).unwrap();
            forest.verify(&3u64, &proofs1[3]).unwrap();
            forest.delete(&0u64, &proofs1[0]).unwrap();
            forest.delete(&3u64, &proofs1[3]).unwrap();

            let (root, _, _) = forest.normalize();
            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[1u64, 2, 4, 5])
            );
        }

        {
            /* delete 0, insert 6, 7:
                d                                          f
                |\                                         | \
                a   b   c      ->        b   c       ->    e   b   c
                |\  |\  |\               |\  |\            |\  |\  |\
                0 1 2 3 4 5          x 1 2 3 4 5 6 7       1 6 2 3 4 5 7
            */
            let mut forest = forest1.clone();
            forest.verify(&0u64, &proofs1[0]).unwrap();
            forest.delete(&0u64, &proofs1[0]).unwrap();
            let proof6 = forest.insert(&6u64);
            let proof7 = forest.insert(&7u64);

            let (root, mut forest2, catchup) = forest.normalize();

            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[1u64, 6, 2, 3, 4, 5, 7])
            );

            let proof6 = catchup.update_proof(&6u64, proof6).unwrap();
            let proof7 = catchup.update_proof(&7u64, proof7).unwrap();
            let proof1 = catchup.update_proof(&1u64, proofs1[1].clone()).unwrap();

            /* delete 1, 7, insert :
                 f                                        g
                 | \                                      | \
                 e   b   c        ->      b   c     ->    b   c
                 |\  |\  |\               |\  |\          |\  |\
                 1 6 2 3 4 5 7        x 6 2 3 4 5 x       2 3 4 5 6
            */

            forest2.verify(&1u64, &proof1).unwrap();
            forest2.verify(&7u64, &proof7).unwrap();
            forest2.delete(&1u64, &proof1).unwrap();
            forest2.delete(&7u64, &proof7).unwrap();

            let (root, mut forest3, catchup) = forest2.normalize();

            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2u64, 3, 4, 5, 6])
            );

            let proof6 = catchup.update_proof(&6u64, proof6).unwrap();
            forest3.delete(&6u64, &proof6).unwrap();
            let (root, _, _) = forest3.normalize();
            assert_eq!(
                root,
                MerkleTree::root::<u64>(b"ZkVM.utreexo", &[2u64, 3, 4, 5])
            );
        }
    }

    #[test]
    fn large_utreexo() {
        let mut forest0 = Forest::new();
        let n = 10_000u64;
        let proofs0 = (0..n).map(|i| forest0.insert(&i)).collect::<Vec<_>>();

        let (_, forest1, catchup1) = forest0.normalize();

        let _proofs1 = proofs0
            .into_iter()
            .enumerate()
            .map(|(i, p)| catchup1.update_proof(&(i as u64), p).unwrap())
            .collect::<Vec<_>>();

        assert!(forest1.metrics().memory < 1600);

        // TODO: perform 1000 changes, normalize again and measure the memory footprint of the Catchup struct.
    }
}
