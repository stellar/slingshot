use crate::merkle::MerkleItem;
use merlin::Transcript;
use std::collections::HashMap;

const UTREEXO_NODE_LABEL: &'static [u8] = b"ZkVM.utreexo.node";
const UTREEXO_ROOT_LABEL: &'static [u8] = b"ZkVM.utreexo.root";

/// Merkle hash of a node
type Hash = [u8; 32];

/// Absolute position of an item in the tree.
type Position = u64;

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
}

/// Index of a `Node` within a forest's heap storage.
#[derive(Copy, Clone, PartialEq, Debug)]
struct NodeIndex {
    index: u32,
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
    trees: Vec<NodeIndex>,          // collection of existing nodes
    inserted_trees: Vec<NodeIndex>, // collection of inserted items
    heap: Vec<Node>,
    node_hasher: NodeHasher,
}

/// Helper structure that allows auto-updating the outdated `Proofs`.
/// The proof's generation should be the catchup generation - 1.
/// The node indices correspond to the forest of the same generation as the Catchup structure.
struct Catchup {
    generation: u64,
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
            inserted_trees: Vec::new(),
            heap: Vec::new(),
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
        let node_index: NodeIndex = self.heap.len().into();
        self.heap.push(node);
        self.inserted_trees.push(node_index);
    }

    /// Fills in the missing nodes in the tree, and marks the item as deleted.
    ///
    /// The algorithm minimizes amount of computation by taking advantage of the already available data.
    ///
    /// Consider the following partially filled tree due to previous operations:
    ///
    /// ```
    /// A         level 4
    /// | \
    /// B  C      level 3
    ///    | \
    ///    D  E   level 2
    /// ```
    ///
    /// Then, an item H is deleted at absolute position 10, with a merkle proof `J',F',E',B'`:
    ///
    /// ```
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
    /// ```
    /// hash(H',J') -> G'
    /// hash(F',G') -> D'
    /// ```
    ///
    /// If D' is not equal to D, reject the proof.
    /// Otherwise, continue walking up the tree to the actual root (A),
    /// but instead of hashing, simply compare remaining steps in the proof with the stored nodes:
    ///
    /// ```
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

        // 1. Locate the most nested node that we have under which the item.position is supposedly located.
        let (top_index, tree_offset) = self.top_node_containing_position(proof.position)?;
        let top_level = self.node_at(&top_index).level;
        let local_position = proof.position - tree_offset;

        // 2. The proof should be of exact size from a leaf up to a tree root.
        if proof.neighbors.len() != top_level as usize {
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 3. Find the lowest-available node in a tree, up to which
        //    we have to fill in the missing nodes based on the merkle proof.
        let lower_index = self.lowest_node_containing_position(top_index, local_position);

        // 4. Now, walk the merkle proof starting with the leaf,
        //    `creating the missing nodes until we hit the lower root.
        let lower_node = self.node_at(&lower_index);
        let mut current = Node {
            root: Node::hash_leaf(self.node_hasher.clone(), item),
            level: 0,
            deletions: 0,
            parent: None,
            children: None,
        };
        let mut new_nodes = Vec::<Node>::with_capacity(2 * lower_node.level as usize);
        for i in 0..lower_node.level {
            let sibling_hash = proof.neighbors[i as usize];
            let mut sibling = Node {
                root: sibling_hash,
                level: current.level,
                deletions: 0,
                parent: None,
                children: None,
            };

            // new nodes are appended to the heap, so we know what the indices would be
            // even before we add new nodes to the heap.
            let curr_i = NodeIndex {
                index: (self.heap.len() + new_nodes.len()) as u32,
            };
            let sibl_i = NodeIndex {
                index: curr_i.index + 1,
            };
            let prnt_i = NodeIndex {
                index: curr_i.index + 2,
            }; // this will be overwritten if parent == lower

            current.parent = Some(prnt_i);
            sibling.parent = Some(prnt_i);

            // reordering of current/sibling is done only for hashing.
            // we guarantee that the current node is always going before the sibling on the heap,
            // to have stable parent index (parent is always stored before its sibling).
            let (l, li, r, ri) = if ((proof.position >> i) & 1) == 0 {
                (&current, curr_i, &sibling, sibl_i)
            } else {
                (&sibling, sibl_i, &current, curr_i)
            };

            let parent_node = Node {
                root: Node::hash_intermediate(self.node_hasher.clone(), &l.root, &r.root),
                level: i + 1,
                deletions: 0,
                parent: None,
                children: Some((li, ri)),
            };

            new_nodes.push(current);
            new_nodes.push(sibling);

            // parent is either added with its sibling on the next iteration, or
            // replaced by a lower_node if it matches it
            current = parent_node;
        }

        // 5. Check if we arrived at a correct lowest-available node.
        if current.root != lower_node.root {
            // We haven't met the node we expected to meet, so the proof is invalid.
            return Err(UtreexoError::InvalidMerkleProof);
        }

        // 6. Check the rest of the merkle proof against all parents up to the top node.
        let mut node_index = lower_index;
        for i in lower_node.level..top_level {
            // parent/children references for intermediate nodes
            // MUST be present in a well-formed forest, so we can unwrap() them.
            let parent_index = self.heap[node_index.index as usize].parent.unwrap();
            let (li, ri) = self.node_at(&parent_index).children.unwrap();
            let bit = (local_position >> i) & 1;
            let neighbor_index = if bit == 0 { ri } else { li };
            if proof.neighbors[i as usize] != self.node_at(&neighbor_index).root {
                return Err(UtreexoError::InvalidMerkleProof);
            }
            node_index = parent_index
        }

        // All checks succeeded: we can now attach new nodes and
        // update the deletions count up to the root.

        // Children should point to the existing lower node
        current.children.map(|(l, r)| {
            (&mut self.heap[l.index as usize]).parent = Some(lower_index);
            (&mut self.heap[r.index as usize]).parent = Some(lower_index);
        });
        // Existing node should point to new children (can be None if the lower node is a leaf)
        let mut lower_node = self.mut_node_at(&lower_index);
        lower_node.children = current.children;

        // Move newly created nodes into the main heap
        let leaf_index: NodeIndex = if lower_node.level == 0 {
            lower_index
        } else {
            // if the lower level was not the leaf, the first new node is the leaf node.
            self.heap.len().into()
        };
        self.heap.extend_from_slice(&new_nodes);

        // Update deletions count for all nodes, starting with the leaf.
        let mut node_index = Some(leaf_index);
        while let Some(i) = node_index {
            let mut node = self.mut_node_at(&i);
            node.deletions += 1;
            node_index = node.parent;
        }

        Ok(())
    }

    /// Normalizes the forest into minimal number of ordered perfect trees.
    /// Returns a new instance of the forest, with defragmented heap, and a Catchup
    /// structure that allows updating the stale proofs (made against the previous Forest generation).
    pub fn normalize(self) -> (Forest, Catchup) {
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

    /// Returns the index of the tree containing an item at a given position,
    /// and the offset of that tree within the set of all items.
    /// `position-offset` would be the position within that tree.
    fn top_node_containing_position(
        &self,
        position: Position,
    ) -> Result<(NodeIndex, Position), UtreexoError> {
        let mut offset: Position = 0;
        let mut root_index: Result<NodeIndex, _> = Err(UtreexoError::ItemOutOfBounds);
        for node_index in self.trees.iter().chain(self.inserted_trees.iter()) {
            let node = self.node_at(node_index);
            let tree_size = node.max_count();
            if position < (offset + tree_size) {
                // this item should be under this top-level node
                root_index = Ok(*node_index);
                break;
            } else {
                offset += tree_size;
            }
        }
        Ok((root_index?, offset))
    }

    /// Returns the index of a lowest available node that contains an item at a given position
    /// within the tree at index `top_index`.
    fn lowest_node_containing_position(
        &self,
        top_index: NodeIndex,
        position: Position,
    ) -> NodeIndex {
        let mut lower_index = top_index;
        while let Some((left, right)) = self.node_at(&lower_index).children {
            let bit = (position >> (self.node_at(&lower_index).level - 1)) & 1;
            lower_index = if bit == 0 { left } else { right };
        }
        lower_index
    }

    fn mut_node_at(&mut self, index: &NodeIndex) -> &mut Node {
        let i = index.index as usize;
        &mut self.heap[i]
    }

    fn node_at(&self, index: &NodeIndex) -> &Node {
        let i = index.index as usize;
        &self.heap[i]
    }
}

impl NodeHasher {
    /// Creates a hasher
    fn new() -> Self {
        Self {
            transcript: Transcript::new(UTREEXO_NODE_LABEL),
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

impl NodeIndex {
    fn none() -> Self {
        NodeIndex {
            index: u32::max_value(),
        }
    }
}

impl From<usize> for NodeIndex {
    fn from(index: usize) -> Self {
        NodeIndex {
            index: index as u32,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

}
