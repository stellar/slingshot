# Utreexo specification

Based on original [Utreexo proposal by Tadge Dryja](https://www.youtube.com/watch?v=edRun-6ubCc).

* [Overview](#overview)
* [Definitions](#definitions)
* [Operations](#operations)
* [Optimizations](#optimizations)


## Overview

This is a specification of a dynamic accumulator for _unspent transaction outputs_
that supports inserts and deletions, costs `O(log(n))` in storage and proof bandwidth,
with efficient update of the accumulator and the membership proofs.

The accumulator consists of a number of perfect merkle binary trees, up to `log(n+1)`,
that can be fully or partially pruned, leaving only their merkle roots.

Accumulator supports five operations:

1. Insert: add a new item to the accumulator.
2. Verify: check that an item exists using its merkle proof.
3. Delete: check that an item exists using its merkle proof, and also mark it as deleted.
4. Normalize: prune deleted items, and normalize the shape of the trees, reducing them to their merkle roots.

New items are added to the end of the list.
Deleted items are verified via the merkle proofs to exit, and marked as deleted without being removed.
Merkle proofs help reconstruct the intermediate nodes in the tree that were previously pruned,
which is used during normalization.

Normalization is required to reduce the space occupied by the accumulator. It requires users to update their proofs,
therefore for ergonomics and also efficiency, normalization does not happen after every operation.
Instead, all operations are applied in batches, temporarily increasing the size of the accumulator,
and then the accumulator is normalized at once, which requires update to the existing merkle proofs.

Normalization consists of the following:

1. All marked items and subtrees with only-deleted items are actually removed.
2. Remaining intermediate nodes are re-organized to form new perfect binary trees:
	* From lowest to highest order `k`, the forest is scanned left-to-right.
	* Each second `k`-tree is merged with the preceding `k`-tree, replacing it with a new `k+1`-tree.
	* If there is only one `k`-tree left, it is left as-is.
3. A _catch-up tree_ is extracted from the new forest.
4. Each tree is pruned, leaving only the merkle roots in the accumulator.

After normalization, every proof against the previous state of the accumulator
becomes invalid and needs to be updated via the _catch-up tree_.

_Catch up tree_ is stored till the next normalization, in order to auto-update proofs that were created
against the previous state of the forest. It is also used to immediately update item proofs
that belong to the user (that are "watched").


## Definitions

### Item

Entity that can be added and removed from the [state](#state) according to the Utreexo protocol. 

### Forest

The _forest_ is an ordered list of [k-trees](#k-tree), from highest `k` to the lowest.

The collection of k-trees unambiguously encodes the total number of items as a sum of `2^k` for each `k`-tree present in the forest.
The forest `{3-tree, 2-tree, 0-tree}` contains 13 items.

### Tree order

The power of two describing the size of the binary tree. [K-tree](#k-tree) has order `k`.

### K-tree

A binary tree of [order](#tree-order) `k`, containing `2^k` items. 0-tree contains a single [item](#item).

### K-tree root

A [Merkle root](#merkle-root) of the [k-tree](#k-tree).

### Merkle root

Leafs and nodes in the tree use the same instance of a Merlin transcript provided by the upstream protocol:

```
T = Transcript(<label>)
```

The hash of an empty list is a 32-byte challenge string with the label `merkle.empty`:

```
MerkleHash(T, {}) = T.challenge_bytes("merkle.empty")
```

The hash of a list with one entry (also known as a leaf hash) is
computed by committing the entry to the transcript (defined by the item type),
and then generating 32-byte challenge string the label `merkle.leaf`:

```
MerkleHash(T, {item}) = {
    T.commit(<field1 name>, item.field1)
    T.commit(<field2 name>, item.field2)
    ...
    T.challenge_bytes("merkle.leaf")
}
```

For n > 1, let k be the largest power of two smaller than n (i.e., k < n ≤ 2k). The merkle hash of an n-element list is then defined recursively as:

```
MerkleHash(T, list) = {
    T.commit("L", MerkleHash(list[0..k]))
    T.commit("R", MerkleHash(list[k..n]))
    T.challenge_bytes("merkle.node")
}
```

### Item proof

Item proof is a tuple `(position, neighbors)` where:

* `position` is an 64-bit unsigned integer indicating absolute index in the set of all items in the [state](#state), 
* `neighbors` is a list of neighboring [merkle roots](#merkle-root) at each level up to (but not including) the [k-tree root](#k-tree-root)
of the [k-tree](#k-tree) that contains this item.

The position of the neighbor root is determined by a correposnding bit in a binary little-endian representation of `position`:
`i`-th bit set to zero means the `i`-th neighbor is to the right of the item.


### Node

A structure with the following fields:

* `root`: a merkle hash.
* `order`: an order of the tree.
* `count`: number of remaining items in the subtree.
* `children`: either a pair of children [Nodes](#node), or _nil_, if the children nodes are pruned.



## Operations

### Insert

Input: 

* [item](#item)

Procedure:

TBD.

### Verify

TBD.

### Watch

TBD.

### Delete

TBD.

### Normalize

TBD.




## Optimizations

### Caching top levels

Caching the top 16 levels of nodes requires only 4Mb of data to store,
but removes up to 512 bytes of data from each proof.

Bandwidth savings at different utxo set sizes and cache sizes.

Levels cached | Required RAM | 1M utxos | 10M  | 100M | 1B
--------------|--------------|----------|------|------|-----
16            | 4 Mb         | 80%      | 66%  | 59%  | 53%
19            | 32 Mb        | 95%      | 79%  | 70%  | 63%
22            | 256 Mb       | 100%     | 91%  | 81%  | 73%
25            | 2048 Mb      | 100%     | 100% | 92%  | 83%

Proof sizes per input in bytes:

Levels cached | Required RAM | 1M utxos | 10M  | 100M | 1B
--------------|--------------|----------|------|------|-----
16            | 4 Mb         | 128      | 256  | 352  | 448
19            | 32 Mb        | 32       | 160  | 256  | 352
22            | 256 Mb       | 0        | 64   | 160  | 256
25            | 2048 Mb      | 0        | 0    | 64   | 160

Notice that as network grows in size, user can have a trade-off between
optimizing bandwidth or optimizing storage. In any case, bandwidth costs grow only linearly
with the exponential growth of the network.

TBD: how the cache is actually maintained.

### Allocation and lookup

TBD: How to allocate tree nodes and speed up the look up w/o wasting too much RAM.


### Catch-up tree

TBD: retaining unmodified nodes from i-1 tree to fixup outdated proofs. 
Can be used for arbitrary steps back, but only one level is actually useful to
provide ergonomic overlay around the point in time where a new commitment is done,
so fresh, but missed-the-mark proofs are not dropped, causing spikes in bandwidth.


### Relaying proofs with different caching options

Cache policy can be decided per node and advertised to its peers upon connection.

For example, let's have nodes A, B, C where A sends a proof to B, who relays it to C.

A and B first establish a connection and B tells A what is B's cache configuration.
Same happens between B and C.

A then sends an appropriately trimmed proof to B. B reconstructs a full proof and verifies it.
If the proof is valid, it is trimmed according to C's cache configuration, and sent to C.

