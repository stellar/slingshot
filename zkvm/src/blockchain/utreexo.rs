use crate::merkle::MerkleItem;
use merlin::Transcript;
use std::collections::HashMap;

/// Merkle hash of a node
type Hash = [u8; 32];

/// Absolute position of an item in the tree.
type Position = u64;

/// Index of a `Node` within a forest's heap storage.
type NodeIndex = usize;

/// Merkle proof of inclusion of a node in a `Forest`.
/// The exact tree is determined by the `position`, an absolute position of the item
/// within the set of all items in the forest.
/// Neighbors are counted from lowest to the highest.
/// Left/right position of the neighbor is determined by the appropriate bit in `position`.
/// (Lowest bit=1 means the first neighbor is to the left of the node.)
/// `generation` points to the generation of the Forest to which the proof applies.
/// `path` is None if this proof is for a newly added item that has no merkle path yet.
struct Proof {
    pub generation: u64,
    pub path: Option<Path>,
}

/// Merkle path to the item.
struct Path {
    position: Position,
    neighbors: Vec<Hash>,
}

/// Node represents a leaf or an intermediate node in one of the trees.
/// Leaves are indicated by `level=0`.
/// Leaves and trimmed nodes have `children=None`.
/// Root nodes have `parent=None`.
#[derive(Copy, Clone, PartialEq, Debug)]
struct Node {
    hash: Hash,
    index: NodeIndex,
    level: u8,
    modified: bool,
    parent: Option<NodeIndex>,
    children: Option<(NodeIndex, NodeIndex)>,
}

/// Packed node as stored in memory.
/// 32 bytes for hash, plus 13 bytes for metadata and parent and children indexes.
/// Flags are: 6 bits for the level 0..63, 1 bit for "modified" and 1 bit for "has children".
/// Missing parent is indicated by 0xffffffff.
#[derive(Copy, Clone, PartialEq, Debug)]
struct PackedNode {
    hash: Hash,
    flags: u8,
    parent: u32,
    children: (u32, u32),
}

#[derive(Clone)]
struct Forest {
    generation: u64,
    trees: Vec<NodeIndex>,         // collection of existing nodes
    insertions: HashMap<Hash, ()>, // new items
    heap: Vec<PackedNode>,
    node_hasher: NodeHasher,
}

#[derive(Clone)]
struct Catchup {
    forest: Forest,                            // forest that stores the nodes
    map: HashMap<Hash, (NodeIndex, Position)>, // node hash -> node index, new position offset for this node
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
            trees: Vec::new(),
            insertions: HashMap::new(),
            heap: Vec::new(),
            node_hasher: NodeHasher::new(),
        }
    }

    /// Verifies the item's proof of inclusion.
    /// TBD: factor out the common pieces.
    pub fn verify<M: MerkleItem>(&self, item: &M, proof: &Proof) -> Result<(), UtreexoError> {
        if proof.generation != self.generation {
            return Err(UtreexoError::OutdatedProof);
        }

        // 0. Fast check: if the proof relates to a newly added item.
        let path = match &proof.path {
            Some(path) => path,
            None => {
                let hash = Node::hash_leaf(self.node_hasher.clone(), item);
                return self
                    .insertions
                    .get(&hash)
                    .map(|x| *x)
                    .ok_or(UtreexoError::InvalidMerkleProof);
            }
        };

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let top = self.top_node_containing_position(path.position)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != top.level as usize {
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        let existing = self.lowest_node_containing_position(top, path.position);

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the bottom node.
        let mut new_nodes = Vec::<Node>::with_capacity(2 * existing.level as usize); // TBD: reuse preallocated scratch-space
        let mut current = self.make_leaf(item);
        for _ in 0..existing.level {
            let heap_offset = (self.heap.len() + new_nodes.len()) as NodeIndex;

            let (parent, (current2, sibling)) =
                self.build_tree_step(current, heap_offset, &path)?;

            new_nodes.push(current2);
            new_nodes.push(sibling);

            // parent is either added with its sibling on the next iteration, or
            // replaced by a lower_node if it matches it
            current = parent;
        }
        let replacement = current;

        // 5. Check if we arrived at a correct lowest-available node.
        if replacement.hash != existing.hash {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // Check the rest of the merkle proof against all parents up to the top node.
        self.check_path_against_tree(existing, &path)?;

        Ok(())
    }

    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert<M: MerkleItem>(&mut self, item: &M) -> Proof {
        // Same position for new items since we look them up by hash.
        // After check point, we'll still look them up by hash.
        // At the same time, position after the pre-existing nodes indicates
        // that this item is an insertion.
        let hash = Node::hash_leaf(self.node_hasher.clone(), item);
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
                let hash = Node::hash_leaf(self.node_hasher.clone(), item);
                return self
                    .insertions
                    .remove(&hash)
                    .ok_or(UtreexoError::InvalidMerkleProof);
            }
        };

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let top = self.top_node_containing_position(path.position)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if path.neighbors.len() != top.level as usize {
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        let existing = self.lowest_node_containing_position(top, path.position);

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the bottom node.
        let mut new_nodes = Vec::<Node>::with_capacity(2 * existing.level as usize); // TBD: reuse preallocated scratch-space
        let mut current = self.make_leaf(item);
        for _ in 0..existing.level {
            let heap_offset = (self.heap.len() + new_nodes.len()) as NodeIndex;

            let (parent, (current2, sibling)) =
                self.build_tree_step(current, heap_offset, &path)?;

            new_nodes.push(current2);
            new_nodes.push(sibling);

            // parent is either added with its sibling on the next iteration, or
            // replaced by a lower_node if it matches it
            current = parent;
        }
        let replacement = current;

        // 5. Check if we arrived at a correct lowest-available node.
        if replacement.hash != existing.hash {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // Check the rest of the merkle proof against all parents up to the top node.
        self.check_path_against_tree(existing, &path)?;

        // All checks succeeded: we can now attach new nodes and
        // update the deletions count up to the root.

        // Connect children to the existing lower node, discarding the new `replacement_node`.
        self.connect_children(existing.index, replacement.children);

        // Move newly created nodes into the main heap
        let leaf_index: NodeIndex = if existing.level == 0 {
            existing.index
        } else {
            // if the lower level was not the leaf, the first new node is the leaf node.
            self.heap.len() as NodeIndex
        };
        self.heap.extend(new_nodes.into_iter().map(|n| n.pack()));

        // Update deletions count for all nodes, starting with the leaf.
        self.mark_as_modified_at(leaf_index);

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
        let mut new_forest = Forest {
            generation: self.generation + 1,
            trees: Vec::new(),
            insertions: HashMap::new(), // will remain empty
            heap: Vec::new(),
            node_hasher: self.node_hasher.clone(),
        };

        // Collect all nodes that were not modified.
        fn collect_non_modified_nodes(forest: &Forest, new_forest: &mut Forest, node: Node) {
            if !node.modified {
                new_forest.add_perfect_tree(node.hash, node.level);
            } else {
                // node is modified - find the non-modified children
                if let Some((l, r)) = node.children {
                    collect_non_modified_nodes(forest, new_forest, forest.node_at(l));
                    collect_non_modified_nodes(forest, new_forest, forest.node_at(r));
                }
            }
        }

        // Add pre-existing unmodified nodes...
        for root_index in self.trees.iter() {
            collect_non_modified_nodes(&self, &mut new_forest, self.node_at(*root_index));
        }

        // ...and newly inserted nodes.
        for (hash, _) in self.insertions.into_iter() {
            new_forest.add_perfect_tree(hash, 0);
        }

        // The `left` variable will flip-flop from None to Some as we match pairs of nodes.
        let mut left: Option<(usize, Node)> = None;

        // This will be used to keep the "last item at a given level"
        // so we can re-order the forest in O(n).
        let mut indices_per_level = [None as Option<NodeIndex>; 64];

        // Scan each level, from low to high, and match up available pairs of nodes, moving
        // the right node closer to the left node.
        for level in 0..64u8 {
            // First, loop over the trees
            let mut i = 0;
            while i < new_forest.trees.len() {
                let node = new_forest.node_at(new_forest.trees[i]);
                if node.level != level {
                    //
                    i += 1;
                    continue;
                }
                if let Some((prev_i, l)) = left {
                    // Remove the right node
                    let ri = new_forest.trees.remove(i);
                    let r = new_forest.node_at(ri);
                    let p = Node {
                        hash: Node::hash_intermediate(
                            new_forest.node_hasher.clone(),
                            &l.hash,
                            &r.hash,
                        ),
                        level: level + 1,
                        index: new_forest.heap.len() as NodeIndex,
                        modified: false,
                        parent: None,
                        children: Some((l.index, r.index)),
                    };
                    new_forest.heap.push(p.pack());

                    // Update parent index for each child.
                    new_forest.update_node_at(l.index, |node| node.parent = Some(p.index));
                    new_forest.update_node_at(r.index, |node| node.parent = Some(p.index));

                    // Replace left child index with the parent index.
                    new_forest.trees[prev_i] = p.index;

                    // Forget the left item as we have successfully matched it up with the right node.
                    left = None;

                    // Clear the remembered level for the left item that we just consumed.
                    // The parent will be remembered in the loop for the level+1.
                    indices_per_level[level as usize] = None;

                // Do not increment `i` since we just removed that item from the list
                // and the current value of `i` now points to the next item (or the end).
                } else {
                    // Remember the first node in the pair
                    left = Some((i, node));

                    // Remember this node's index for this level.
                    indices_per_level[level as usize] = Some(node.index);
                    i += 1;
                }
            }
            // if there was no matching right node, leave the left one in the tree,
            // forgetting it before we go to the higher level.
            left = None;
        }

        // Reorder the trees so that higher-level trees go first.
        // We already remembered the latest node index per level, so just fill the trees list with those.
        new_forest.trees.truncate(0);
        for maybe_node_index in indices_per_level.into_iter().rev() {
            // rev() because higher-level trees go first
            if let Some(index) = maybe_node_index {
                new_forest.trees.push(*index);
            }
        }

        // Create a new, trimmed forest.
        let mut trimmed_forest = Forest {
            generation: new_forest.generation,
            trees: Vec::with_capacity(self.trees.len()), // filled in below
            insertions: HashMap::new(),                  // will remain empty
            heap: Vec::with_capacity(self.trees.len()),  // filled in below
            node_hasher: new_forest.node_hasher.clone(),
        };

        // Traverse the tree to collect the catchup entries
        let mut catchup_map: HashMap<Hash, (NodeIndex, Position)> = HashMap::new();
        fn collect_catchup_entries(
            forest: &Forest,
            catchup_map: &mut HashMap<Hash, (NodeIndex, Position)>,
            node: Node,
            offset: Position,
        ) {
            if let Some((l, r)) = node.children {
                let (left, right) = (forest.node_at(l), forest.node_at(r));
                collect_catchup_entries(forest, catchup_map, left, offset);
                collect_catchup_entries(forest, catchup_map, right, offset + left.capacity());
            } else {
                catchup_map.insert(node.hash, (node.index, offset));
            }
        }
        let mut offset: Position = 0;
        for root_index in self.trees.iter() {
            let root = new_forest.node_at(*root_index);
            offset += root.capacity();
            trimmed_forest.add_perfect_tree(root.hash, root.level);
            collect_catchup_entries(&new_forest, &mut catchup_map, root, offset);
        }

        let catchup = Catchup {
            forest: new_forest,
            map: catchup_map,
        };

        // TODO: hash the root of the forest.
        let root = unimplemented!();

        (root, trimmed_forest, catchup)
    }

    /// Makes a leaf node
    fn make_leaf<M: MerkleItem>(&self, item: &M) -> Node {
        Node {
            hash: Node::hash_leaf(self.node_hasher.clone(), item),
            index: self.heap.len() as NodeIndex,
            level: 0,
            modified: false,
            parent: None,
            children: None,
        }
    }

    /// Adds a perfect tree to the forest
    fn add_perfect_tree(&mut self, hash: Hash, level: u8) {
        let node = Node {
            hash,
            index: self.heap.len() as NodeIndex,
            level: level,
            modified: false,
            parent: None,   // forget parent - there will be a new one in the new forest
            children: None, // trim children
        };
        self.heap.push(node.pack());
        self.trees.push(node.index);
    }

    /// Builds a new node
    fn build_tree_step(
        &self,
        mut current: Node,
        heap_offset: NodeIndex,
        path: &Path,
    ) -> Result<(Node, (Node, Node)), UtreexoError> {
        // new nodes are appended to the heap, so we know what the indices would be
        // even before we add new nodes to the heap.
        let curr_i = heap_offset;
        let sibl_i = heap_offset + 1;
        let prnt_i = heap_offset + 2;

        PackedNode::validate_index(prnt_i as usize)?;

        current.parent = Some(prnt_i);

        let sibling = Node {
            hash: path.neighbors[current.level as usize],
            index: sibl_i,
            level: current.level,
            modified: false,
            parent: Some(prnt_i),
            children: None,
        };

        // reordering of current/sibling is done only for hashing.
        // we guarantee that the current node is always going before the sibling on the heap,
        // to have stable parent index (parent is always stored before its sibling).
        let (l, li, r, ri) = if ((path.position >> current.level) & 1) == 0 {
            (&current, curr_i, &sibling, sibl_i)
        } else {
            (&sibling, sibl_i, &current, curr_i)
        };

        let parent_node = Node {
            hash: Node::hash_intermediate(self.node_hasher.clone(), &l.hash, &r.hash),
            level: current.level + 1,
            index: prnt_i,
            modified: false,
            parent: None,
            children: Some((li, ri)),
        };

        Ok((parent_node, (current, sibling)))
    }

    /// Checks the relevant tail of the merkle proof against existing nodes
    /// starting with a given node index. This uses precomputed hashes stored in the tree,
    /// without hashing anything at all.
    fn check_path_against_tree(&self, mut node: Node, path: &Path) -> Result<(), UtreexoError> {
        let top_level = path.neighbors.len() as u8; // the correctness of the path length is checked by the caller
        for i in node.level..top_level {
            // parent/children references for intermediate nodes
            // MUST be present in a well-formed forest.
            let parent_index = node.parent.ok_or(UtreexoError::InternalInconsistency)?;
            let (li, ri) = node.children.ok_or(UtreexoError::InternalInconsistency)?;
            let bit = (path.position >> i) & 1;
            let neighbor_index = if bit == 0 { ri } else { li };
            if path.neighbors[i as usize] != self.hash_at(neighbor_index) {
                return Err(UtreexoError::InvalidMerkleProof);
            }
            node = self.node_at(parent_index);
        }
        Ok(())
    }

    /// Sets the parent/children references between the nodes at the given indices.
    fn connect_children(
        &mut self,
        parent_index: NodeIndex,
        children: Option<(NodeIndex, NodeIndex)>,
    ) {
        children.map(|(l, r)| {
            let _ = self.update_node_at(l, |node| node.parent = Some(parent_index));
            let _ = self.update_node_at(r, |node| node.parent = Some(parent_index));
        });
        // Existing node should point to new children (can be None if the lower node is a leaf)
        let _ = self.update_node_at(parent_index, |node| node.children = children);
    }

    /// Returns the index of the tree containing an item at a given position,
    /// and the offset of that tree within the set of all items.
    /// `position-offset` would be the position within that tree.
    fn top_node_containing_position(&self, position: Position) -> Result<Node, UtreexoError> {
        let mut offset: Position = 0;
        for node_index in self.trees.iter() {
            let node = self.node_at(*node_index);
            offset += node.capacity();
            if position < offset {
                return Ok(node);
            }
        }
        Err(UtreexoError::ItemOutOfBounds)
    }

    /// Returns the index of a lowest available node that contains an item at a given position
    /// within the tree at index `top_index`.
    fn lowest_node_containing_position(&self, mut node: Node, position: Position) -> Node {
        while let Some((left, right)) = node.children {
            let level2 = node.level - 1;
            let bit = (position >> level2) & 1;
            let i = if bit == 0 { left } else { right };
            node = self.node_at(i);
        }
        node
    }

    /// Marks the node as modified and updates modified flag in all its parent nodes.
    fn mark_as_modified_at(&mut self, index: NodeIndex) {
        let mut index = Some(index);
        while let Some(i) = index {
            index = self.update_node_at(i, |node| node.modified = true).parent;
        }
    }

    fn update_node_at(&mut self, i: NodeIndex, closure: impl FnOnce(&mut Node)) -> Node {
        let mut node = self.heap[i as usize].unpack(i);
        closure(&mut node);
        self.heap[i as usize] = node.pack();
        node
    }

    fn node_at(&self, i: NodeIndex) -> Node {
        self.heap[i as usize].unpack(i)
    }

    fn hash_at(&self, i: NodeIndex) -> Hash {
        self.heap[i as usize].hash
    }
}

impl Catchup {
    // Updates the proof if it's slightly out of date
    // (made against the previous generation of the Utreexo).
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

        // For the newly added items position is irrelevant, so we create a dummy placeholder
        let mut path = proof.path.unwrap_or(Path {
            position: 0,
            neighbors: Vec::new(),
        });

        let mut hash = self.forest.make_leaf(item).hash;
        let mut catchup_result = self.map.get(&hash);
        let mut i = 0;
        // Climb up the merkle path until we find an existing node or nothing.
        while i < path.neighbors.len() && catchup_result == None {
            let (l, r) = if (path.position >> i) & 1 == 0 {
                (hash, path.neighbors[i])
            } else {
                (path.neighbors[i], hash)
            };
            hash = Node::hash_intermediate(self.forest.node_hasher.clone(), &l, &r);
            catchup_result = self.map.get(&hash);
            i += 1;
        }

        // Fail early if we did not find any catchup point.
        let (index, position_offset) = catchup_result.ok_or(UtreexoError::InvalidMerkleProof)?;
        let catchup_node = self.forest.node_at(*index);

        // Adjust the absolute position:
        // keep the lowest (level+1) bits and add the stored position offset for the stored subtree
        let mask: Position = (1 << catchup_node.level) - 1; // L=0 -> ...00, L=1 -> ...01, L=2 -> ...11
        path.position = position_offset + (path.position & mask);

        // Remove all outdated neighbors
        path.neighbors.truncate(i);

        // Insert updated neighbors
        let mut parent_index = catchup_node.parent;
        while let Some(pi) = parent_index {
            let p = self.forest.node_at(pi);
            let (l, r) = p.children.unwrap();
            let neighbor_index = if (path.position >> (p.level - 1)) & 1 == 0 {
                r
            } else {
                l
            };
            path.neighbors.push(self.forest.hash_at(neighbor_index));
            parent_index = p.parent;
        }

        Ok(Proof {
            generation: self.forest.generation,
            path: Some(path),
        })
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

    fn pack(&self) -> PackedNode {
        debug_assert!(self.level < 64);

        let p = self
            .parent
            .map(|p| {
                let p = p as u32;
                debug_assert!(p != 0xffffffff);
                p
            })
            .unwrap_or(0xffffffff) as u32;

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
            flags: self.level + modflag + chflag,
            parent: p,
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
            level: self.flags & 63,
            modified: (self.flags & 64) == 64,
            parent: if self.parent == 0xffffffff {
                None
            } else {
                Some(self.parent as NodeIndex)
            },
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
    fn test_utreexo() {
        let forest0 = Forest::new();

        //forest0.
    }
}
