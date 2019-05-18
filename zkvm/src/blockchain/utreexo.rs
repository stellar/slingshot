use crate::merkle::MerkleItem;
use merlin::Transcript;

const UTREEXO_NODE_LABEL: &'static [u8] = b"ZkVM.utreexo.node";
const UTREEXO_ROOT_LABEL: &'static [u8] = b"ZkVM.utreexo.root";

type Hash = [u8; 32];

/// Represents an error in proof creation, verification, or parsing.
#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum UtreexoError {
    /// This error occurs when we receive a proof that's outdated and cannot be auto-updated.
    #[fail(display = "Item proof is outdated and must be re-created against the new state")]
    OutdatedProof,

    /// This error occurs when we the item in the proof is out of bounds
    #[fail(display = "Item proof contains position that is out of bounds")]
    ItemOutOfBounds,
}

struct NodeIndex {
    index: u32,
}

struct Node {
    root: Hash,
    flags: u8,      // packed fields { generation mod 2, has_children: 0/1, order: 0..63 }
    deletions: u32, // number of deleted items in this subtree
    parent: NodeIndex, // no parent is identified by u32::max_value()
    children: (NodeIndex, NodeIndex), // has meaning only if has_children == 1
}

struct Forest {
    generation: u64,
    trees: Vec<NodeIndex>, // indices into the `heap`.
    heap: Vec<Node>,
}

struct Proof {
    generation: u64,
    position: u64,
    neighbors: Vec<Hash>,
}

struct Catchup {}

impl Default for Forest {
    fn default() -> Self {
        Forest {
            generation: 0,
            trees: Vec::new(),
            heap: Vec::new(),
        }
    }
}

impl Forest {
    // /// Creates a new non-normalized forest from a list of items
    // pub fn new<I>(label: &'static [u8], generation: u64, items: I) -> Self
    // where
    // I: IntoIterator,
    // I::IntoIter: ExactSizeIterator,
    // I::Item: MerkleItem
    // {
    //     let items = items.into_iter();
    //     let t = Transcript::new(label);
    //     let n = items.len();

    //     // // there is a tree for each `1` bit in the binary encoding of `n`.
    //     // let trees = Vec::with_capacity(n.count_ones() as usize);

    //     // // Create binary trees in place, keeping intermediate nodes in the buffer.
    //     // // The leftover nodes will perfectly match the necessary trees,
    //     // // from bigger to smaller.
    //     // for item in items {
    //     //     let mut hash = [0u8;32];
    //     //     Self::hash_leaf(t.clone(), &item, &mut hash);

    //     //     let mut new_node = Node {
    //     //         root: hash,
    //     //         order: 0,
    //     //         count: 1,
    //     //         children: None,
    //     //     };

    //     //     // TBD: maybe defer this to a normalization stage?
    //     //     while let Some(node) = trees.pop() {
    //     //         // if we already have the node of the same order - merge them together.
    //     //         // continue doing so until we don't have any prior nodes, or if the prior nodes are of too big order.
    //     //         if node.order == new_node.order {
    //     //             Self::hash_intermediate(t.clone(), &node.root, &new_node.root, &mut hash);
    //     //             let parent_node = Node {
    //     //                 root: hash,
    //     //                 order: node.order + 1,
    //     //                 count: new_node.count + node.count,
    //     //                 children: Some((Box::new(node), Box::new(new_node)))
    //     //             }
    //     //             new_node = parent_node;
    //     //         } else {
    //     //             trees.push(node); // put existing node back
    //     //         }
    //     //     }
    //     //     trees.push(new_node);
    //     // }

    //     // Forest { trees }
    // }

    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert<M: MerkleItem>(&mut self, item: &M) {
        let node = Node::leaf(item, self.generation + 1);
        let node_index = self.add_node(node);
        self.trees.push(node_index);
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

        // Locate the most nested node that we have under which the item.position
        // is supposedly located.
        // 1. Find the tree.
        let mut offset: u64 = 0;
        let mut root: Result<&Node, _> = Err(UtreexoError::ItemOutOfBounds);
        for node_index in self.trees.iter() {
            let node = &self.heap[node_index.index as usize];
            let tree_size = node.max_count();
            if proof.position < (offset + tree_size) {
                // this item should be under this top-level node
                root = Ok(node);
                break;
            } else {
                offset += tree_size;
            }
        }
        let mut root = root?;
        // 2. Drill into the tree to locate the inner-most node.
        while let Some((left, right)) = root.children() {
            root = if ((proof.position - offset) >> (root.order() - 1)) & 1 == 0 {
                &self.heap[left.index as usize]
            } else {
                &self.heap[right.index as usize]
            }
        }

        // Now, walk the merkle proof until we hit the `root`.
        // Also, create all necessary nodes on the go, and if we meet the root,
        // add all of them into the heap.

        // create a node for the item.

        let mut nodes = Vec::<Node>::new();
        for i in 0..root.order() {

            // create the sibling node, and the parent.
        }

        // check if the node equals the root.
        // if it does, set the node's children's parent to the root's index.
        // update root's children.
        // append all nodes to the heap.

        // while root has a parent, verify the rest of the proof
        // to make sure the proof is valid all by itself.

        unimplemented!()
    }

    /// Normalizes the forest into minimal number of ordered perfect trees.
    /// Returns a new instance of the forest, with defragmented heap, and a Catchup
    /// structure that allows updating the stale proofs (made against the previous generation).
    pub fn normalize(&mut self) -> (Forest, Catchup) {
        // 1. Scan k = 0 .. max order
        // 2. Skip fully removed subtrees (max_count == deletions)
        // 3. Create new nodes connecting same-sized pairs
        // 4. Accumulate new roots in a new `trees` vector.
        // 5. Create Catchup structure walking the new `trees` vector:
        //    for each of the prev-generator node - do not traverse, but add the record:
        //      hash -> (node index, offset)
        //    also create a new buffer of nodes, so we don't store unnecessary data till next normalization.
        // 6. Create new forest with trimmed roots, while keeping the Catchup structure until next normalization

        unimplemented!()
    }

    fn add_node(&mut self, node: Node) -> NodeIndex {
        let node_index: NodeIndex = self.heap.len().into();
        self.heap.push(node);
        node_index
    }

    fn mut_node_at(&mut self, index: NodeIndex) -> Option<&mut Node> {
        let i = index.index as usize;
        if index.index == u32::max_value() || i > self.heap.len() {
            None
        } else {
            Some(&mut self.heap[i])
        }
    }

    fn node_at(&self, index: NodeIndex) -> Option<&Node> {
        let i = index.index as usize;
        if index.index == u32::max_value() || i > self.heap.len() {
            None
        } else {
            Some(&self.heap[i])
        }
    }
}

impl Node {
    /// Creates a leaf node with a given generation
    fn leaf<M: MerkleItem>(item: &M, generation: u64) -> Self {
        let t = Transcript::new(UTREEXO_NODE_LABEL);
        let mut hash = [0u8; 32];
        Self::hash_leaf(t, item, &mut hash);

        Self {
            root: hash,
            flags: Self::pack_flags(generation, false, 0),
            deletions: 0,
            parent: NodeIndex::none(),
            children: (NodeIndex::none(), NodeIndex::none()),
        }
    }

    fn pack_flags(generation: u64, has_children: bool, order: u8) -> u8 {
        // make sure order is in bounds
        assert!(order <= 0b0011_1111);

        (((generation % 2) << 7) as u8) | if has_children { 0b0100_0000 } else { 0 } | order
    }

    fn generation_mod_2(&self) -> u8 {
        self.flags & 0b1000_0000
    }

    fn has_children(&self) -> bool {
        self.flags & 0b0100_0000 == 1
    }

    fn children(&self) -> Option<(NodeIndex, NodeIndex)> {
        if self.has_children() {
            Some(self.children)
        } else {
            None
        }
    }

    /// order of the tree - from 0 to 63.
    fn order(&self) -> u8 {
        self.flags & 0b0011_1111
    }

    /// maximum number of items in this subtree, ignoring deletions
    fn max_count(&self) -> u64 {
        1 << self.order()
    }

    /// number of remaining items in this subtree, accounting for deletions
    fn remaining_count(&self) -> u64 {
        self.max_count() - (self.deletions as u64)
    }

    fn hash_leaf<M: MerkleItem>(mut t: Transcript, item: &M, result: &mut [u8; 32]) {
        item.commit(&mut t);
        t.challenge_bytes(b"merkle.leaf", result);
    }

    fn hash_intermediate(mut t: Transcript, left: &[u8], right: &[u8], result: &mut [u8; 32]) {
        t.commit_bytes(b"L", left);
        t.commit_bytes(b"R", right);
        t.challenge_bytes(b"merkle.node", result);
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
