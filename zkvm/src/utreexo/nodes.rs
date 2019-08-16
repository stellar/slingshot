use core::marker::PhantomData;
use merlin::Transcript;
use serde::{Deserialize, Serialize};

use super::path::{Position, Side};
use crate::merkle::{Hash, MerkleItem};

/// Index of a `Node` within a forest's heap storage.
pub(super) type NodeIndex = usize;

/// Precomputed hash instance for computing Utreexo trees.
pub struct NodeHasher<M: MerkleItem> {
    t: Transcript,
    phantom: PhantomData<M>,
}

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
#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
pub(super) struct Node {
    pub(super) hash: Hash,
    pub(super) index: NodeIndex,
    pub(super) level: usize,
    pub(super) modified: bool,
    pub(super) children: Option<(NodeIndex, NodeIndex)>,
}

impl Node {
    /// maximum number of items in this subtree, ignoring deletions
    pub(super) fn capacity(&self) -> u64 {
        1 << self.level
    }

    /// Returns the index in the iterator of hashes where the position must be located.
    pub(crate) fn find_root<I, F>(roots: I, level: F, position: Position) -> Option<I::Item>
    where
        I: IntoIterator,
        F: Fn(&I::Item) -> usize,
    {
        let mut offset: Position = 0;
        for item in roots.into_iter() {
            offset += 1u64 << level(&item);
            if position < offset {
                return Some(item);
            }
        }
        None
    }

    fn pack(&self) -> PackedNode {
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
/// TBD: serialize as a packed binary string.
#[derive(Copy, Clone, PartialEq, Debug, Serialize, Deserialize)]
struct PackedNode {
    hash: Hash,
    flags: u8,
    children: (u32, u32),
}

impl<M: MerkleItem> NodeHasher<M> {
    /// Creates a new hasher instance.
    pub fn new() -> Self {
        NodeHasher {
            t: Transcript::new(b"ZkVM.utreexo"),
            phantom: PhantomData,
        }
    }

    pub(super) fn leaf(&self, item: &M) -> Hash {
        let mut t = self.t.clone();
        item.commit(&mut t);
        let mut hash = Hash::default();
        t.challenge_bytes(b"merkle.leaf", &mut hash);
        hash
    }

    pub(super) fn intermediate(&self, left: &Hash, right: &Hash) -> Hash {
        let mut t = self.t.clone();
        t.append_message(b"L", &left);
        t.append_message(b"R", &right);
        let mut hash = Hash::default();
        t.challenge_bytes(b"merkle.node", &mut hash);
        hash
    }

    pub(super) fn empty(&self) -> Hash {
        let mut t = self.t.clone();
        let mut hash = Hash::default();
        t.challenge_bytes(b"merkle.empty", &mut hash);
        hash
    }
}

impl PackedNode {
    fn unpack(&self, index: NodeIndex) -> Node {
        let level = (self.flags & 63) as usize;
        Node {
            hash: self.hash,
            index,
            level,
            modified: self.flags & 64 == 64,
            children: if self.flags & 128 == 0 {
                None
            } else {
                Some((self.children.0 as NodeIndex, self.children.1 as NodeIndex))
            },
        }
    }
}

/// Storage of all the nodes with methods to access them.
#[derive(Clone, Serialize, Deserialize)]
pub(super) struct Heap {
    storage: Vec<PackedNode>,
}

impl Heap {
    pub(super) fn with_capacity(cap: usize) -> Self {
        Heap {
            storage: Vec::with_capacity(cap),
        }
    }

    pub(super) fn node_at(&self, i: NodeIndex) -> Node {
        self.storage[i].unpack(i)
    }

    pub(super) fn len(&self) -> usize {
        self.storage.len()
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
