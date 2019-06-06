use crate::merkle::MerkleItem;
use core::marker::PhantomData;
use core::mem;
use merlin::Transcript;
use std::collections::HashMap;

use super::bitarray::Bitarray;
use super::path::{Position,Path,Directions,Side};

/// Merkle hash of a node
pub type Hash = [u8; 32];

/// Index of a `Node` within a forest's heap storage.
pub(super) type NodeIndex = usize;


impl<M: MerkleItem> Clone for NodeHasher<M> {
    fn clone(&self) -> Self {
        Self {
            t: self.t.clone(),
            phantom: self.phantom,
        }
    }
}

/// Node represents a leaf or an intermediate node in one of the trees.
/// Leaves are indicated by `level=0`.
/// Leaves and trimmed nodes have `children=None`.
/// Root nodes have `parent=None`.
#[derive(Copy, Clone, PartialEq, Debug)]
pub(super) struct Node {
    hash: Hash,
    index: NodeIndex,
    level: usize,
    modified: bool,
    children: Option<(NodeIndex, NodeIndex)>,
}

impl Node {
    /// maximum number of items in this subtree, ignoring deletions
    pub(super) fn capacity(&self) -> u64 {
        1 << self.level
    }

    pub(super) fn pack(&self) -> PackedNode {
        debug_assert!(self.level < 64);

        let modflag = if self.modified { 64 } else { 0 };

        let (chflag, (l, r)) = self
            .children
            .map(|(l, r)| (128, (l as u32, r as u32)))
            .unwrap_or((0, (0xffffffff, 0xffffffff)));

        PackedNode {
            hash: self.hash,
            flags: (self.level as u8) + modflag + chflag,
            children: (l, r),
        }
    }
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




pub(super) struct NodeHasher<M: MerkleItem> {
    t: Transcript,
    phantom: PhantomData<M>,
}

impl<M: MerkleItem> NodeHasher<M> {
    fn new() -> Self {
        NodeHasher {
            t: Transcript::new(b"ZkVM.utreexo"),
            phantom: PhantomData,
        }
    }

    fn leaf(&self, item: &M) -> Hash {
        let mut t = self.t.clone();
        item.commit(&mut t);
        let mut hash = [0; 32];
        t.challenge_bytes(b"merkle.leaf", &mut hash);
        hash
    }

    fn intermediate(&self, left: &Hash, right: &Hash) -> Hash {
        let mut t = self.t.clone();
        t.commit_bytes(b"L", left);
        t.commit_bytes(b"R", right);
        let mut hash = [0; 32];
        t.challenge_bytes(b"merkle.node", &mut hash);
        hash
    }

    fn empty(&self) -> Hash {
        let mut t = self.t.clone();
        let mut hash = [0; 32];
        t.challenge_bytes(b"merkle.empty", &mut hash);
        hash
    }
}


impl PackedNode {
    fn unpack(&self, index: NodeIndex, modified: bool) -> Node {
        let level = (self.flags & 63) as usize;
        Node {
            hash: self.hash,
            index,
            level,
            modified,
            children: if self.flags & 128 == 0 {
                None
            } else {
                Some((self.children.0 as NodeIndex, self.children.1 as NodeIndex))
            },
        }
    }
}

/// Storage of all the nodes with methods to access them.
#[derive(Clone)]
pub(super) struct Heap {
    storage: Vec<PackedNode>,
    modification_flags: Bitarray,
}

impl Heap {
    pub(super) fn with_capacity(cap: usize) -> Self {
        Heap {
            storage: Vec::with_capacity(cap),
            modification_flags: Bitarray::with_capacity(cap)
        }
    }

    pub(super) fn node_at(&self, i: NodeIndex) -> Node {
        self.storage[i].unpack(i, self.modification_flags.bit_at(i))
    }

    pub(super) fn len(&self) -> usize {
        self.storage.len()
    }

    /// Perform allocations in a transaction block: all allocations are removed
    /// if the block fails.
    pub(super) fn transaction<T, E>(
        &mut self,
        closure: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let pre_transaction_size = self.storage.len();
        let pre_transaction_modflags = self.modification_flags.clone();

        match closure(&mut self) {
            Ok(x) => Ok(x),
            Err(e) => {
                // undo all newly allocated items, but keep the allocated capacity for future use
                self.storage.truncate(pre_transaction_size);
                // disconnect all the children if the node was previously unmodified
                for (i, (before, after)) in pre_transaction_modflags.iter().zip(self.modification_flags.iter()).enumerate().take(pre_transaction_size) {
                    if !before && after {
                        let node = self.storage[i].unpack(i, before);
                        node.children = None;
                        self.storage[i] = node.pack();
                    }
                }
                self.modification_flags = pre_transaction_modflags;
                Err(e)
            }
        }
    }

    /// Allocates a node in the heap.
    pub(super) fn allocate(
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

    pub(super) fn update(&mut self, i: NodeIndex, closure: impl FnOnce(&mut Node)) -> Node {
        let mut node = self.node_at(i);
        closure(&mut node);
        self.storage[i] = node.pack();
        self.modification_flags.set_bit_at(i, node.modified);
        node
    }

    pub(super) fn traverse<'h, F>(
        &'h self,
        roots: impl IntoIterator<Item = Node>,
        predicate: F,
    ) -> TreeTraversal<'h, F>
    where
        F: for<'n> Fn(&'n Node) -> bool,
    {
        TreeTraversal::new(self, roots, predicate)
    }

    /// Returns an iterator that walks the given path (from root down)
    /// and yields current node and its neighbor.
    /// * Root node is NOT included.
    /// * The last node yielded by the iterator is the node without children.
    /// * If the root has no children, iterator yields None on the first iteration.
    pub(super) fn walk_down<'a, 'b: 'a>(
        &'a self,
        root: Node,
        directions: impl IntoIterator<Item = Side> + 'b,
    ) -> impl Iterator<Item = (Node, Node)> + '_ {
        directions
            .into_iter()
            .scan(root.children, move |children, side| {
                children.map(|(li, ri)| {
                    let (main, neighbor) = side.choose(self.node_at(li), self.node_at(ri));
                    *children = main.children;
                    (main, neighbor)
                })
            })
    }

    pub(super) fn memory(&self) -> usize {
    	self.storage.len() * mem::size_of::<PackedNode>()
    }
}


/// Iterator implementing traversal of the binary tree.
pub(super) struct TreeTraversal<'h, F>
where
    F: for<'n> Fn(&'n Node) -> bool,
{
    /// reference to the heap of nodes
    heap: &'h Heap,
    /// drill-down predicate - if it returns true, iterator traverses to the children.
    /// if it returns false, the node is yielded, but its children are ignored.
    predicate: F,
    /// nodes in the queue - next node to be yielded is in the end of the list
    nodes: Vec<(Position, NodeIndex)>,
}

impl<'h, F> TreeTraversal<'h, F>
where
    F: for<'n> Fn(&'n Node) -> bool,
{
    fn new(heap: &'h Heap, roots: impl IntoIterator<Item = Node>, predicate: F) -> Self {
        let mut roots = roots.into_iter().peekable();
        let cap = roots.size_hint().0 + 2 * roots.peek().map(|r| r.level).unwrap_or(0);
        let mut t = TreeTraversal {
            heap,
            predicate,
            nodes: Vec::with_capacity(cap),
        };
        let mut offset = 0;
        for r in roots {
            // insert in reverse order because the frontier of the iteration
            // will be in the end of the list.
            t.nodes.insert(0, (offset, r.index));
            offset += r.capacity();
        }
        t
    }
}

impl<'h, F> Iterator for TreeTraversal<'h, F>
where
    F: for<'n> Fn(&'n Node) -> bool,
{
    type Item = (Position, Node);
    fn next(&mut self) -> Option<Self::Item> {
        if let Some((offset, ni)) = self.nodes.pop() {
            let node = self.heap.node_at(ni);
            if (self.predicate)(&node) {
                if let Some((li, ri)) = node.children {
                    self.nodes.push((offset + node.capacity() / 2, ri));
                    self.nodes.push((offset, li));
                }
            }
            Some((offset, node))
        } else {
            None
        }
    }
}

