use crate::merkle::MerkleItem;

type Hash =[u8; 32];

struct Node {
    root: Hash,
    order: u8,
    generation: u8, // TBD: pack into order
    count: u64,
    children: Option<(Box<Node>, Box<Node>)>
}

struct Forest {
    trees: Vec<Node>
}

struct Proof {
    position: u64,
    neighbors: Vec<Hash>
}

impl Default for Forest {
    fn default() -> Self {
        Forest { trees: Vec::new() }
    }
}

impl Forest {

    /// Creates a new non-normalized forest from a list of items
    pub fn new<I>(label: &'static [u8], items: I) -> Self
    where  
    I: IntoIterator,
    I::IntoIter: ExactSizeIterator,
    I::Item: MerkleItem
    {
        let t = Transcript::new(label);
        let n = items.len();

        // there is a tree for each `1` bit in the binary encoding of `n`.
        let trees = Vec::with_capacity(n.count_ones() as usize);

        // Create binary trees in place, keeping intermediate nodes in the buffer.
        // The leftover nodes will perfectly match the necessary trees,
        // from bigger to smaller.
        for item in items {
            let mut hash = [0u8;32];
            Self::hash_leaf(t.clone(), item, &mut hash);

            let mut new_node = Node {
                root: hash,
                order: 0,
                count: 1,
                children: None,
            };

            // TBD: maybe defer this to a normalization stage?
            while let Some(node) = trees.pop() {
                // if we already have the node of the same order - merge them together.
                // continue doing so until we don't have any prior nodes, or if the prior nodes are of too big order.
                if node.order == new_node.order {
                    Self::hash_intermediate(t.clone(), &node.root, &new_node.root, &mut hash);
                    let parent_node = Node {
                        root: hash,
                        order: node.order + 1,
                        count: new_node.count + node.count,
                        children: Some((Box::new(node), Box::new(new_node)))
                    }
                    new_node = parent_node;
                } else {
                    trees.push(node); // put existing node back
                }
            }
            trees.push(new_node);
        }
        
        Forest { trees }
    }

    /// Adds a new item to the tree, appending a node to the end.
    pub fn insert<M: MerkleItem>(&mut self, item: &M) {
        let mut hash = [0u8;32];
        Self::hash_leaf(t.clone(), item, &mut hash);
        self.trees.push(Node{
            root: hash,
            order: 0,
            count: 1,
            children: None,
        })
    }

    pub fn delete<M: MerkleItem>(&mut self, item: &M, ) {

    }


    fn hash_leaf<M: MerkleItem>(mut t: Transcript, item: &M, result: &mut [u8; 32]) {
        item.commit(&mut t);
        t.challenge_bytes(b"merkle.leaf", result);
    }

    fn hash_intermediate(mut t: Transcript, left: &[u8], right: &[u8], result: &mut [u8; 32]) {
        t.commit_bytes(b"L", left);
        t.commit_bytes(b"R", right);
        t.challenge_bytes(b"merkle.node", &mut result);
    }

    /// Normalizes the forest into minimal number of ordered perfect trees.
    /// TBD: maybe split normalized/denormalized into two types.
    /// Although, we need to serialize both versions, so maybe we simply need to normalize
    /// when we do a checkpoint.
    pub fn normalize(&mut self) {
        unimplemented!()
    }

}