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
        let t = Transcript::new(UTREEXO_NODE_LABEL);
        let mut hash = [0u8; 32];
        Self::hash_leaf(t, item, &mut hash);

        let node = Node {
            root: hash,
            flags: Node::pack_flags(self.generation + 1, false, 0),
            deletions: 0,
            parent: NodeIndex::none(),
            children: (NodeIndex::none(), NodeIndex::none()),
        };

        let node_index: NodeIndex = self.heap.len().into();
        self.heap.push(node);
        self.trees.push(node_index);
    }

    pub fn delete<M: MerkleItem>(&mut self, item: &M, proof: &Proof) -> Result<(), UtreexoError> {}

    fn mut_node_at(&mut self, index: NodeIndex) -> Option<&mut Node> {
        if index == u32::max_value() || index > self.heap.len() {
            None
        } else {
            Some(&mut self.heap[index.index])
        }
    }

    fn node_at(&self, index: NodeIndex) -> Option<&Node> {
        if index.index == u32::max_value() || index.index > self.heap.len() {
            None
        } else {
            Some(&self.heap[index.index])
        }
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

    /// Normalizes the forest into minimal number of ordered perfect trees.
    /// TBD: maybe split normalized/denormalized into two types.
    /// Although, we need to serialize both versions, so maybe we simply need to normalize
    /// when we do a checkpoint.
    pub fn normalize(&mut self) {
        unimplemented!()
    }
}

impl Node {
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

    fn children(&self) -> Option<(u32, u32)> {
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

    /// number of remaining items in this subtree, discounting deletions
    fn remaining_count(&self) -> u64 {
        (1 << self.order()) - (self.deletions as u64)
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
