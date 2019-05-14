# Utreexo specification

Based on original [Utreexo proposal by Tadge Dryja](https://www.youtube.com/watch?v=edRun-6ubCc).

## Introduction

This is a specification of a dynamic accumulator for _unspent transaction outputs_
that supports inserts and deletions, costs `O(log(n))` in storage and proof bandwidth,
with efficient update of the accumulator and the membership proofs.

## Definitions

### Item

Entity that can be added and removed from the [state](#state) according to the Utreexo protocol. 

### State

The state is defined as an ordered list of [k-tree roots](#k-tree-root), from highest `k` to the lowest.

The list unambiguously encodes the total number of items as a sum of `2^k` for each `k`-tree present in the state.
The state `{3-tree, 2-tree, 0-tree}` contains 13 items.

### K-tree

A binary tree of exactly `2^k` items. Each individual [item](#item) is a _0-tree_.

### K-tree root

A [Merkle root](#merkle-root) of the [k-tree](#k-tree).

### Merkle root

TBD: hashing algo for intermediate nodes

TBD: hashing algo for item-into-node

### Item proof

Item proof is a tuple `(position, neighbors)` where:

* `position` is an 64-bit unsigned integer indicating absolute index in the set of all items in the [state](#state), 
* `neighbors` is a list of neighboring [merkle roots](#merkle-root) at each level up to (but not including) the [k-tree root](#k-tree-root)
of the [k-tree](#k-tree) that contains this item.

The position of the neighbor root is determined by a correposnding bit in a binary little-endian representation of `position`:
`i`-th bit set to zero means the `i`-th neighbor is to the right of the item.

### Work state

An intermediate presentation of the [state](#state) in process of update that contains [work roots](#work-root).

### Work root

Work root:

```
{
	offset: u64, # number of items preceding items in this tree (including deleted ones)
	k-order: log(size),
	sibling: Option<Hash> # nil if it's an original root,
	watch: Option<WatchNode>
}
```

## Algorithm

### Create work state

Input: a [state](#state).

Output: a [work state](#work-state).

Procedure:

TBD.

### Verify item

TBD:

### Delete item

TBD: 
