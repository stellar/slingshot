use crate::merkle::MerkleItem;
use merlin::Transcript;
use std::collections::HashMap;

/// Merkle hash of a node
type Hash = [u8; 32];

/// Absolute position of an item in the tree.
type Position = u64;

/// Index of a `Node` within a forest's heap storage.
type NodeIndex = u32;

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
}

/// Node represents a leaf or an intermediate node in one of the trees.
/// Leaves are indicated by `level=0`.
/// Leaves and trimmed nodes have `children=None`.
/// Root nodes have `parent=None`.
#[derive(Copy, Clone, PartialEq, Debug)]
struct Node {
    root: Hash,
    level: u8,
    deletions: u32,
    parent: Option<NodeIndex>,
    children: Option<(NodeIndex, NodeIndex)>,
}

struct Forest {
    generation: u64,
    trees: Vec<NodeIndex>,      // collection of existing nodes
    insertions: Vec<NodeIndex>, // collection of inserted items
    heap: Vec<Node>,
    // helper structure that allows auto-updating the outdated `Proofs`.
    catchup: HashMap<Hash, (NodeIndex, Position)>, // node hash -> node index, new position offset for this node
    node_hasher: NodeHasher,
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
            catchup: HashMap::new(),
            node_hasher: NodeHasher::new(),
        }
    }
}

impl Forest {
    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert<M: MerkleItem>(&mut self, item: &M) {
        let node = Node {
            root: Node::hash_leaf(self.node_hasher.clone(), item),
            level: 0,
            deletions: 0,
            parent: None,
            children: None,
        };
        let node_index = self.heap.len() as NodeIndex;
        self.heap.push(node);
        self.insertions.push(node_index);
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
        // TBD.
        // if (proof.generation+1) == self.generation {
        //     proof = self.catchup(proof)?;
        // }
        if proof.generation != self.generation {
            return Err(UtreexoError::OutdatedProof);
        }

        // 0. Fast check: if the proof relates to a newly added item, simply remove it,
        //    so that transient items do not take up space until normalization.
        let ins_offset = self.insertions_offset();
        if proof.position >= ins_offset {
            let i = proof.position - ins_offset;
            if proof.neighbors.len() != 0 {
                // proof must be empty
                return Err(UtreexoError::InvalidMerkleProof);
            }
            self.insertions.remove(i as usize);
            return Ok(());
        }

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let top_index = self.top_node_containing_position(proof.position)?;
        let top_level = self.node_at(top_index).level;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if proof.neighbors.len() != top_level as usize {
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        let lower_index = self.lowest_node_containing_position(top_index, proof.position);

        // 4. Now, walk the merkle proof starting with the leaf,
        //    creating the missing nodes until we hit the lower root.
        let lower_node = self.node_at(lower_index);
        let lower_level = lower_node.level;
        let mut new_nodes = Vec::<Node>::with_capacity(2 * lower_level as usize);

        let mut current = Node {
            root: Node::hash_leaf(self.node_hasher.clone(), item),
            level: 0,
            deletions: 0,
            parent: None,
            children: None,
        };
        for i in 0..lower_level {
            let heap_offset = (self.heap.len() + new_nodes.len()) as NodeIndex;

            let (parent, (current2, sibling)) =
                self.build_tree_step(current, heap_offset, i, &proof);

            new_nodes.push(current2);
            new_nodes.push(sibling);

            // parent is either added with its sibling on the next iteration, or
            // replaced by a lower_node if it matches it
            current = parent;
        }

        // 5. Check if we arrived at a correct lowest-available node.
        if current.root != lower_node.root {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 6. Check the rest of the merkle proof against all parents up to the top node.
        self.check_proof_against_tree(lower_index, &proof)?;

        // All checks succeeded: we can now attach new nodes and
        // update the deletions count up to the root.

        // Connect children to the existing lower node, discarding the `current` node.
        self.connect_children(lower_index, current.children);

        // Move newly created nodes into the main heap
        let leaf_index: NodeIndex = if lower_level == 0 {
            lower_index
        } else {
            // if the lower level was not the leaf, the first new node is the leaf node.
            self.heap.len() as NodeIndex
        };
        self.heap.extend_from_slice(&new_nodes);

        // Update deletions count for all nodes, starting with the leaf.
        self.mark_as_deleted(leaf_index);

        Ok(())
    }

    /// Normalizes the forest into minimal number of ordered perfect trees.
    /// Returns a new instance of the forest, with defragmented heap.
    pub fn normalize(self) -> Forest {
        // 1. Relocate all perfect nodes (w/o deletions) nodes into a new forest.
        // 2. Scan levels from 0 to max level, connecting pairs of the closest same-level nodes.
        // 3. Traverse the entire tree creating Catchup entries with new offsets for all old leaves
        //    without children (ignoring new leaves).
        // 4. Return the resulting Forest and Catchup structure.
        //
        // Note: the forest is not fully trimmed - for Catchup to work, it contains intermediate nodes
        // between the new roots and the old intermediate nodes.

        unimplemented!()
    }

    // /// Catches up the proof
    // fn catchup(&self, ) -> (Proof, ) {

    // }

    /// Builds a new node
    fn build_tree_step(
        &self,
        mut current: Node,
        heap_offset: NodeIndex,
        level: u8,
        proof: &Proof,
    ) -> (Node, (Node, Node)) {
        // new nodes are appended to the heap, so we know what the indices would be
        // even before we add new nodes to the heap.
        let curr_i = heap_offset;
        let sibl_i = heap_offset + 1;
        let prnt_i = heap_offset + 2;

        current.parent = Some(prnt_i);

        let sibling = Node {
            root: proof.neighbors[level as usize],
            level,
            deletions: 0,
            parent: Some(prnt_i),
            children: None,
        };

        // reordering of current/sibling is done only for hashing.
        // we guarantee that the current node is always going before the sibling on the heap,
        // to have stable parent index (parent is always stored before its sibling).
        let (l, li, r, ri) = if ((proof.position >> level) & 1) == 0 {
            (&current, curr_i, &sibling, sibl_i)
        } else {
            (&sibling, sibl_i, &current, curr_i)
        };

        let parent_node = Node {
            root: Node::hash_intermediate(self.node_hasher.clone(), &l.root, &r.root),
            level: level + 1,
            deletions: 0,
            parent: None,
            children: Some((li, ri)),
        };

        (parent_node, (current, sibling))
    }

    /// Checks the relevant tail of the merkle proof against existing nodes
    /// starting with a given node index. This uses precomputed hashes stored in the tree,
    /// without hashing anything at all.
    fn check_proof_against_tree(
        &self,
        mut node_index: NodeIndex,
        proof: &Proof,
    ) -> Result<(), UtreexoError> {
        let lower_level = self.node_at(node_index).level;
        let top_level = proof.neighbors.len() as u8; // the correctness of the proof length is checked by the caller
        for i in lower_level..top_level {
            // parent/children references for intermediate nodes
            // MUST be present in a well-formed forest.
            let parent_index = self
                .node_at(node_index)
                .parent
                .ok_or(UtreexoError::InternalInconsistency)?;
            let (li, ri) = self
                .node_at(parent_index)
                .children
                .ok_or(UtreexoError::InternalInconsistency)?;
            let bit = (proof.position >> i) & 1;
            let neighbor_index = if bit == 0 { ri } else { li };
            if proof.neighbors[i as usize] != self.node_at(neighbor_index).root {
                return Err(UtreexoError::InvalidMerkleProof);
            }
            node_index = parent_index
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
            self.mut_node_at(l).parent = Some(parent_index);
            self.mut_node_at(r).parent = Some(parent_index);
        });
        // Existing node should point to new children (can be None if the lower node is a leaf)
        let mut parent = self.mut_node_at(parent_index);
        parent.children = children;
    }

    /// Returns the index of the tree containing an item at a given position,
    /// and the offset of that tree within the set of all items.
    /// `position-offset` would be the position within that tree.
    fn top_node_containing_position(&self, position: Position) -> Result<NodeIndex, UtreexoError> {
        let mut offset: Position = 0;
        let mut root_index: Result<NodeIndex, _> = Err(UtreexoError::ItemOutOfBounds);
        for node_index in self.trees.iter() {
            let node = self.node_at(*node_index);
            let tree_size = node.max_count();
            if position < (offset + tree_size) {
                // this item should be under this top-level node
                root_index = Ok(*node_index);
                break;
            } else {
                offset += tree_size;
            }
        }
        root_index
    }

    /// Offset of all inserted items.
    /// Same as the count of all items after normalization, without considering
    /// deletions and insertions.
    fn insertions_offset(&self) -> Position {
        self.trees
            .iter()
            .map(|i| self.node_at(*i).max_count())
            .sum()
    }

    /// Returns the index of a lowest available node that contains an item at a given position
    /// within the tree at index `top_index`.
    fn lowest_node_containing_position(
        &self,
        top_index: NodeIndex,
        position: Position,
    ) -> NodeIndex {
        let mut i = top_index;
        while let Some((left, right)) = self.node_at(i).children {
            let level = self.node_at(i).level - 1;
            let bit = (position >> level) & 1;
            i = if bit == 0 { left } else { right };
        }
        i
    }

    /// Marks the node as deleted and updates deletions counters in all its parent nodes.
    fn mark_as_deleted(&mut self, index: NodeIndex) {
        let mut index = Some(index);
        while let Some(i) = index {
            let mut node = self.mut_node_at(i);
            node.deletions += 1;
            index = node.parent;
        }
    }

    fn mut_node_at(&mut self, i: NodeIndex) -> &mut Node {
        &mut self.heap[i as usize]
    }

    fn node_at(&self, i: NodeIndex) -> &Node {
        &self.heap[i as usize]
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
    fn max_count(&self) -> u64 {
        1 << self.level
    }

    /// number of remaining items in this subtree, accounting for deletions
    fn remaining_count(&self) -> u64 {
        self.max_count() - (self.deletions as u64)
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
}

#[cfg(test)]
mod tests {
    use super::*;

}
