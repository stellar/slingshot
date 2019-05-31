# Utreexo specification

Inspired by the original [Utreexo proposal by Tadge Dryja](https://www.youtube.com/watch?v=edRun-6ubCc).

* [Overview](#overview)
* [Definitions](#definitions)
* [Operations](#operations)
* [Optimizations](#optimizations)


## Overview

This is a specification of a dynamic accumulator for _unspent transaction outputs_
that supports inserts and deletions, costs `O(log(n))` in storage and proof bandwidth,
with efficient update of the accumulator and the membership proofs.

The accumulator consists of a number of perfect merkle binary trees, up to `log(n)`,
that can be fully or partially pruned, leaving only their merkle roots.

Accumulator supports the following operations:

1. **Insert:** add a new item to the accumulator and create a proof for it.
2. **Verify:** check that an item exists using its merkle proof.
3. **Delete:** check that an item exists using its merkle proof, and also mark it as deleted.
4. **Normalize:** prune deleted items, and normalize the shape of the trees, reducing them to their merkle roots.
5. **Update proof:** update the merkle proof created against the previous state of the accumulator (before most recent normalization).

Normalization is required to reduce the space occupied by the accumulator.
Users must update their proofs upon every normalization.

All proofs for items inserted before normalization are `O(1)` in length.
Increasing the time interval between normalizations allows trading off storage for lower bandwidth.

Normalization does the following:

1. Extracts all nodes that were not marked as modified (that is, subtrees that do not contain items marked as deleted).
2. Reorganizes the remaining nodes to form new perfect binary trees.
3. A _catch up structure_ is created mapping all preserved nodes to their new positions.
4. The collection of trees is pruned, leaving only the merkle roots in the accumulator.

After normalization, every proof against the previous state of the accumulator
becomes invalid and needs to be updated via the _catch up structure_.

_Catch up structure_ is stored till the next normalization, in order to auto-update proofs that were created
against the previous state of the forest.
It is also used to update the stored proofs for the outputs _watched_ by the node.


## Definitions

### Item

Entity that can be added and removed from the [forest](#forest).

### Forest

Forest is a structure with the following fields:

* `generation`: a [generation](#generation) of the forest.
* `roots`: an ordered list of [nodes](#node) each representing a [k-tree](#k-tree), from highest `k` to the lowest.
* `insertions`: an ordered list of [item hashes](#merkle-root).

The list of roots unambiguously encodes the total number of items as a sum of `2^k` for each `k`-tree present in the forest.
The forest with `{3-tree, 2-tree, 0-tree}` roots and no insertions contains 13 items.

### Generation

The sequence number of the [forest](#forest) incremented each time it is normalized.
Represented as a 64-bit unsigned integer.

### Tree level

The power of two describing the size of the binary tree. [K-tree](#k-tree) has level `k`.

### K-tree

A binary tree of [level](#tree-level) `k`, containing `2^k` items. 0-tree contains a single [item](#item).

### K-tree root

A [Merkle root](#merkle-root) of the [k-tree](#k-tree).

### Merkle root

Leafs and nodes in the tree use the same instance of a Merlin transcript initialized as:

```
T = Transcript("ZkVM.utreexo")
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

For `n > 1`, let `k` be the largest power of two smaller than `n` (i.e., `k < n ≤ 2k`). The merkle hash of an `n`-element list is then defined recursively as:

```
MerkleHash(T, list) = {
    T.commit("L", MerkleHash(list[0..k]))
    T.commit("R", MerkleHash(list[k..n]))
    T.challenge_bytes("merkle.node")
}
```

### Item proof

Item proof is a structure with three fields:

* `generation`: a 64-bit unsigned integer indicating the generation of the [forest](#forest).
* `position`: a 64-bit unsigned integer indicating absolute index in the set of all items in the [forest](#forest),
* `neighbors`: a list of neighboring [merkle roots](#merkle-root) at each level up to (but not including) the [k-tree root](#k-tree-root)
of the [k-tree](#k-tree) that contains this item.

The position of the neighbor root is determined by a correposnding bit in a binary little-endian representation of `position`:
`i`-th bit set to zero means the `i`-th neighbor is to the right of the item.


### Node

A structure with the following fields:

* `root`: a merkle hash.
* `level`: an order of the tree.
* `modified`: a boolean indicating
* `children`: either a pair of [nodes](#node), or _nil_, if the children are pruned or this node has level 0.


### Catchup

A structure with the following fields:

* `forest`: the non-pruned forest of the next [generation](#generation) to which the proofs are updated.
* `map` linking a [hash](#merkle-root) of a [node](#node) to its absolute position in the new [forest](#forest).





## Operations

### Insert

Inputs: [forest](#forest), [item](#item).

Returns [item proof](#item-proof).

1. Compute item’s [leaf hash](#merkle-root).
2. Append it to the `forest.insertions` list.
3. Return a proof with:
	* `generation`: the current [generation](#generation) of the forest,
	* `position` set to the index in the insertions list, offset by the total number of items in the forest,
	* `neighbors` list: empty.



### Verify

Inputs: [forest](#forest), [item](#item), [item proof](#item-proof).

Returns `true` or `false`.

1. Verify that the item proof’s [generation](#generation) is equal to the generation of the forest.
2. If the position is past the number of items under the forest roots, check the presence of the item in the insertions list.
   If the item’s [leaf hash](#merkle-root) is present in the insertions, return `true`; otherwise return `false`.
3. Find the [root node](#node) `r` in the forest that contains the item’s position.
4. Verify that the number of neighbors in the proof is equal to the `r.level`.
5. Find the lowest-level available [node](#node) `b` in the `r`’s subtree that contains the item’s position (`b` is equal to `r` if `r` has pruned children or has level 0).
   Verify that the corresponding neighbors in the proof are equal to the actual higher-level neighbors (from `r.level-1` to `b.level`) along the way toward the `b`.
6. Compute the intermediate hashes using the item and its lower-level neighbors from `0` to `b.level-1`.
7. Verify that the resulting hash is equal to the hash of node `b`.
8. Return `true` if all checks succeeded.


### Delete

Inputs: [forest](#forest), [item](#item), [item proof](#item-proof).

Returns `true` or `false`.

1. Verify that the item proof’s [generation](#generation) is equal to the generation of the forest.
2. If the position is past the number of items under the forest roots, check the presence of the item in the insertions list.
   If the item’s [leaf hash](#merkle-root) is present in the insertions, return `true`; otherwise return `false`.
3. Find the [root node](#node) `r` in the forest that contains the item’s position.
4. Verify that the number of neighbors in the proof is equal to the `r.level`.
5. Find the lowest-level available [node](#node) `b` in the `r`’s subtree that contains the item’s position (`b` is equal to `r` if `r` has pruned children or has level 0).
   Verify that the corresponding neighbors in the proof are equal to the actual higher-level neighbors (from `r.level-1` to `b.level`) along the way toward the `b`.
6. Compute the intermediate hashes using the item and its lower-level neighbors from `0` to `b.level-1`.
7. Verify that the resulting hash is equal to the hash of node `b`.
8. If all checks succeeded:
	1. Add newly created nodes on the way from the item to `b` at step 6, including the neighbors and the node for the item itself to the tree `r`.
	2. Mark all the nodes containing the item as `modified`, from the item’s node to the root `r`.
	3. Return `true`.
9. If any check failed, return `false`.


### Normalize

Input: [forest](#forest).

Returns [forest root](#merkle-root), [new forest](#forest), [catchup structure](#catchup).

1. Traverse forest [trees](#k-tree), from left to right, collecting the unmodified [nodes](#node) in a list.
   * Note: the unmodified nodes must not have children.
2. Append to the list all the insertions, in order, as level-0 [nodes](#node).
3. Process the collected nodes, from left to right, keeping track of the latest node at each level `k`:
	1. As long as there is an already remembered node `l` at the same level `k` as current node `r`:
		1. Forget the `l`, create a new parent node with level `k+1` with children `l` and `r`.
		2. Set `r` to the new parent node and repeat, creating higher-level parents until there’s no longer a remembered node to join with.
	2. Remember the resulting node `r` at its level.
4. Create a new [forest](#forest) with new roots formed by all remembered nodes in the previous step, incremented generation, and an empty insertions list.
5. Create a [catchup](#catchup) structure with the new forest and the map created as follows:
	1. Traverse the new forest, picking only the nodes without children.
	2. For each such node, add a pair `(hash, offset)` where offset is the offset of all the items’ positions in this node’s subtree.
6. Create a copy of the new forest with all the roots having their subtrees completely pruned: this will be the new forest to which updates.
7. Compute the complete [merkle root](#merkle-root) of the entire new forest by hashing pairs of roots from end to the beginning. This is equivalent to computing the [merkle root](#merkle-root) over the entire set of items, if they were all stored.
8. Return the root of the new forest, the pruned forest and the catchup structure.



### Update proof

Input: [catchup structure](#catchup), [item](#item) and [item proof](#item-proof).

Returns new [item proof](#item-proof) or failure.

1. If the generation of the proof is equal to the generation of the `catchup.forest`, return the proof unchanged.
2. If the generation of the proof is not equal to the previous generation of the `catchup.forest`, fail.
3. Compute intermediate hashes using the proof’s neighbors until meeting a hash present in the catchup map.
4. If reached the end of the proof, but no matching hash is found in the map, fail.
5. Let `k` be the level of the remembered node (`k` can be zero, if the item’s leaf node was remembered).
6. Erase all but first `k` bits of the item’s position in the proof, and increase it by the offset in stored in the catchup map with the matching hash.
7. Erase all the neighbors in the proof past the `k` hashes.
8. Walk the new forest from the catch up node to the root, appending all the neighbors to the proof.
9. Return the updated proof.



## Optimizations

### Normalization window

The Utreexo forest can be normalized at arbitrary intervals,
limited only by amount of memory to store intermediate nodes in the trees before they are pruned by normalization.

Larger normalization interval permits saving bandwidth for recently added nodes, as their merkle proofs are effectively empty,
but requires more storage.


### Caching top levels

Caching the top 16 levels of nodes requires only ≈4Mb of data to store,
but removes 512 bytes of data from each proof.

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

TBD: how the cached hashes are actually maintained during normalization.

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

