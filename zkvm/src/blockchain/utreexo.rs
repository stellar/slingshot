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
struct Proof {
    generation: u64,
    position: Position,
    neighbors: Vec<Hash>,
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

/// Node represents a leaf or an intermediate node in one of the trees.
/// Leaves are indicated by `level=0`.
/// Leaves and trimmed nodes have `children=None`.
/// Root nodes have `parent=None`.
#[derive(Copy, Clone, PartialEq, Debug)]
struct Node {
    root: Hash,
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
    root: Hash,
    flags: u8,
    parent: u32,
    children: (u32, u32),
}

#[derive(Clone)]
struct Forest {
    generation: u64,
    trees: Vec<NodeIndex>, // collection of existing nodes
    insertions: Vec<Hash>, // hashes of newly inserted items
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

impl Default for Forest {
    fn default() -> Self {
        Forest {
            generation: 0,
            trees: Vec::new(),
            insertions: Vec::new(),
            heap: Vec::new(),
            node_hasher: NodeHasher::new(),
        }
    }
}

impl Forest {
    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert<M: MerkleItem>(&mut self, item: &M) {
        let hash = Node::hash_leaf(self.node_hasher.clone(), item);
        self.insertions.push(hash);
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
        let ins_offset = self.insertions_offset();
        if proof.position >= ins_offset {
            let i = (proof.position - ins_offset) as usize;
            if proof.neighbors.len() != 0 {
                // proof must be empty
                return Err(UtreexoError::InvalidMerkleProof);
            }
            // make sure the deleted item actually matches the stored hash
            if self.insertions[i] == Node::hash_leaf(self.node_hasher.clone(), item) {
                self.insertions.remove(i as usize);
                return Ok(());
            } else {
                return Err(UtreexoError::InvalidMerkleProof);
            }
        }

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let top = self.top_node_containing_position(proof.position)?;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if proof.neighbors.len() != top.level as usize {
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        let existing = self.lowest_node_containing_position(top, proof.position);

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the bottom node.
        let mut new_nodes = Vec::<Node>::with_capacity(2 * existing.level as usize); // TBD: reuse preallocated scratch-space
        let mut current = self.make_leaf(item);
        for _ in 0..existing.level {
            let heap_offset = (self.heap.len() + new_nodes.len()) as NodeIndex;

            let (parent, (current2, sibling)) =
                self.build_tree_step(current, heap_offset, &proof)?;

            new_nodes.push(current2);
            new_nodes.push(sibling);

            // parent is either added with its sibling on the next iteration, or
            // replaced by a lower_node if it matches it
            current = parent;
        }
        let replacement = current;

        // 5. Check if we arrived at a correct lowest-available node.
        if replacement.root != existing.root {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // Check the rest of the merkle proof against all parents up to the top node.
        self.check_proof_against_tree(existing, &proof)?;

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
    /// Returns a new instance of the forest, with defragmented heap.
    pub fn normalize(self) -> (Forest, Catchup) {
        // 1. Relocate all perfect nodes (w/o deletions) into a new forest.
        // 2. Scan levels from 0 to max level, connecting pairs of the closest same-level nodes.
        // 3. Traverse the entire tree creating Catchup entries with new offsets for all old leaves
        //    without children (ignoring new leaves).
        // 4. Extract a thinner Forest structure to return separately,
        //    so it can be kept while Catchup can be optionally discarded.
        //
        // Note: the forest is not fully trimmed - for Catchup to work, it contains intermediate nodes
        // between the new roots and the old intermediate nodes.
        fn collect_non_modified_nodes(buf: &mut Vec<PackedNode>, node_index: NodeIndex) {
            let node = self.node_at(node_index);
            if !node.modified {
                buf.push
            }
        }

        let mut new_trees = Vec::<PackedNode>::new();

        for root in self.trees.iter() {
            collect_non_modified_nodes(&mut new_trees)
        }


        unimplemented!()
    }

    /// Makes a leaf node
    fn make_leaf<M: MerkleItem>(&self, item: &M) -> Node {
        Node {
            root: Node::hash_leaf(self.node_hasher.clone(), item),
            index: self.heap.len() as NodeIndex,
            level: 0,
            modified: false,
            parent: None,
            children: None,
        }
    }

    /// Builds a new node
    fn build_tree_step(
        &self,
        mut current: Node,
        heap_offset: NodeIndex,
        proof: &Proof,
    ) -> Result<(Node, (Node, Node)), UtreexoError> {
        // new nodes are appended to the heap, so we know what the indices would be
        // even before we add new nodes to the heap.
        let curr_i = heap_offset;
        let sibl_i = heap_offset + 1;
        let prnt_i = heap_offset + 2;

        PackedNode::validate_index(prnt_i as usize)?;

        current.parent = Some(prnt_i);

        let sibling = Node {
            root: proof.neighbors[current.level as usize],
            index: sibl_i,
            level: current.level,
            modified: false,
            parent: Some(prnt_i),
            children: None,
        };

        // reordering of current/sibling is done only for hashing.
        // we guarantee that the current node is always going before the sibling on the heap,
        // to have stable parent index (parent is always stored before its sibling).
        let (l, li, r, ri) = if ((proof.position >> current.level) & 1) == 0 {
            (&current, curr_i, &sibling, sibl_i)
        } else {
            (&sibling, sibl_i, &current, curr_i)
        };

        let parent_node = Node {
            root: Node::hash_intermediate(self.node_hasher.clone(), &l.root, &r.root),
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
    fn check_proof_against_tree(&self, mut node: Node, proof: &Proof) -> Result<(), UtreexoError> {
        let top_level = proof.neighbors.len() as u8; // the correctness of the proof length is checked by the caller
        for i in node.level..top_level {
            // parent/children references for intermediate nodes
            // MUST be present in a well-formed forest.
            let parent_index = node.parent.ok_or(UtreexoError::InternalInconsistency)?;
            let (li, ri) = node.children.ok_or(UtreexoError::InternalInconsistency)?;
            let bit = (proof.position >> i) & 1;
            let neighbor_index = if bit == 0 { ri } else { li };
            if proof.neighbors[i as usize] != self.root_at(neighbor_index) {
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

    /// Offset of all inserted items.
    /// Same as the count of all items after normalization, without considering
    /// deletions and insertions.
    fn insertions_offset(&self) -> Position {
        self.trees.iter().map(|i| self.node_at(*i).capacity()).sum()
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

    /// Marks the node as deleted and updates deletions counters in all its parent nodes.
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

    fn root_at(&self, i: NodeIndex) -> Hash {
        self.heap[i as usize].root
    }
}

impl Catchup {
    // Updates the proof in place.
    pub fn update_proof<M: MerkleItem>(
        &self,
        item: &M,
        mut proof: Proof,
    ) -> Result<Proof, UtreexoError> {
        if self.forest.generation == 0 || proof.generation != self.forest.generation - 1 {
            return Err(UtreexoError::OutdatedProof);
        }

        let mut hash = self.forest.make_leaf(item).root;
        for i in 0..proof.neighbors.len() {
            if let Some((index, position_offset)) = self.map.get(&hash) {
                let catchup_node = self.forest.node_at(*index);

                // Adjust the absolute position:
                // keep the lowest (level+1) bits and add the stored position offset for the stored subtree
                let mask: Position = (1 << catchup_node.level) - 1; // L=0 -> ...00, L=1 -> ...01, L=2 -> ...11
                proof.position = position_offset + (proof.position & mask);

                // Remove all outdated neighbors
                proof.neighbors.truncate(i);

                // Insert updated neighbors
                let mut parent_index = catchup_node.parent;
                while let Some(pi) = parent_index {
                    let p = self.forest.node_at(pi);
                    let (l, r) = p.children.unwrap();
                    let neighbor_index = if (proof.position >> (p.level - 1)) & 1 == 0 {
                        r
                    } else {
                        l
                    };
                    proof.neighbors.push(self.forest.root_at(neighbor_index));
                    parent_index = p.parent;
                }
                return Ok(proof);
            }

            let (l, r) = if (proof.position >> i) & 1 == 0 {
                (hash, proof.neighbors[i])
            } else {
                (proof.neighbors[i], hash)
            };
            hash = Node::hash_intermediate(self.forest.node_hasher.clone(), &l, &r);
        }

        Err(UtreexoError::InvalidMerkleProof)
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

        let mut p = self
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
            root: self.root,
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
            root: self.root,
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

}
