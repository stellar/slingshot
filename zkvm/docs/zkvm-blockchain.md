# ZkVM blockchain specification

This is the specification for the ZkVM blockchain,
a blockchain containing
[ZkVM transactions](zkvm-spec.md).

Nodes participating in a ZkVM blockchain network must implement the data types and perform the procedures described in this document.

This document does not describe the consensus mechanism for a ZkVM blockchain network.

# Data types

## Blockchain state

The state of a ZkVM blockchain is given by the blockchain-state structure.
As each new [block](#block) arrives,
it is [applied](#apply-block) to the current state to produce an new,
updated state.

The blockchain state contains:

- `initialheader`:
  The initial block header
  (at height 1).
  This never changes.
- `tipheader`:
  The latest block header.
- `utxos`:
  The set of current
  [utxo IDs](zkvm-spec.md#utxo).
- `nonces`:
  The set of current
  [nonce anchors](zkvm-spec.md#nonce).
- `refids`:
  The set of recent
  [block IDs](#block-id).
  The size of this set is bounded by `block.header.refscount`.
  Block IDs in this set may be referenced by nonces.

## Block

A block contains:

- `header`:
  a
  [block header](#block-header).
- `txs`:
  a list of
  [transactions](zkvm-spec.md#transaction).

The initial block (at height 1) has an empty list of transactions.

## Block header

A block header contains:

- `version`:
  integer version number,
  set to 1.
- `height`:
  integer block height.
  Initial block has height 1.
  Height increases by 1 with each new block.
- `previd`:
  ID of the preceding block.
  For the initial block
  (which has no predecessor),
  this is an all-zero string of 32 bytes.
- `timestampms`:
  integer timestamp of the block in milliseconds since the Unix epoch:
  00:00:00 UTC Jan 1,
  1970.
  Each new block must have a time strictly later than the block before it.
- `txroot`:
  32-byte [Merkle root hash](zkvm-spec.md#merkle-binary-tree) of the transactions in the block.
- `utxoroot`:
  32-byte [Merkle patricia root hash](#merkle-patricia-tree) of the utxo set after applying all transactions in the block.
- `nonceroot`:
  32-byte [Merkle patricia root hash](#merkle-patricia-tree) of the nonce set after applying all transactions in the block.
- `refscount`:
  integer number of recent block IDs to store for reference.
  A new block may specify a lower `refscount` than its predecessor but may not increase it by more than 1.

## Block ID

A block ID is computed from a
[block header](#block-header)
using the
[transcript](zkvm-spec.md#transcript)
mechanism:

```
T = Transcript("ZkVM.blockheader")
T.commit(LE64(version))
T.commit(LE64(height))
T.commit(previd)
T.commit(LE64(timestampms))
T.commit(txroot)
T.commit(utxoroot)
blockid = T.challenge_bytes("id")
```

## Merkle patricia tree

A Merkle patricia tree is similar to a [Merkle binary tree](zkvm-spec.md#merkle-binary-tree).
Each node hashes the subtrees beneath it.
The root node’s hash is a commitment to the full membership of the tree.
It is possible to create and verify compact proofs of membership.

Unlike a Merkle binary tree,
a Merkle patricia tree is a radix tree
(in which subtrees of a given node share a common prefix)
with variable length branches that allow for efficient updates.
It is therefore preferable to a Merkle binary tree for sets with churn
specifically the utxo set and the nonce set.

As with the Merkle binary tree,
we define a Merkle patricia tree in terms of
[transcripts](zkvm-spec.md#transcript).
Leaves and nodes in the tree use the same instance of a transcript:

```
T = Transcript(<label>)
```

(where `<label>` is specified by the calling protocol).

The input to the *Merkle patricia tree hash*
(MPTH)
is a list of data entries;
these entries will be hashed to form the leaves of the merkle hash tree.
The output is a single 32-byte hash value.
The input list must be prefix-free;
that is,
no element can be a prefix of any other.
Given a sorted list of n unique inputs,
`D[n] = {d(0), d(1), ..., d(n-1)}`,
the MPTH is thus defined as follows:

The hash of an empty Merkle patricia tree list is a 32-byte challenge string with the label `patricia.empty`:

```
MPTH(T, {}) = T.challenge_bytes("patricia.empty")
```

To compute the hash of a list with one entry,
commit it to the transcript with the label `"patricia.leaf"` and then generate a 32-byte challenge string with the same label:

```
T.commit("patricia.leaf", d(0))
MPTH(T, {d{0)}) = T.challenge_bytes("patricia.leaf")
```

To compute the hash of a list with two or more entries:
1. Let the bit string `p` be the longest common prefix of all entries;
2. Let k be the number of items with prefix `p||0`
   (that is, `p` concatenated with the single bit 0).
3. Let L be recursively defined as `MPTH(T, D[0:k])` (the hash of the first `k` elements of D).
4. Commit `L` to `T` with the label `"patricia.left"`.
5. Let R be recursively defined as `MPTH(T, D[k:n])` (the hash of the remaining `n-k` elements of D).
5. Commit `R` to `T` with the label `"patricia.right"`.
6. Generate a 32-byte challenge string with the label `"patricia.node"`.

```
T.commit("patricia.left", MPTH(T, D[0:k]))
T.commit("patricia.right", MPTH(T, D[k:n]))
MPTH(T, D) = T.challenge_bytes("patricia.node")
```

# Procedures

## Start new network

Inputs:
- `timestampms`, the current time as a number of milliseconds since the Unix epoch:
  00:00:00 UTC Jan 1,
  1970.
- `refscount`, the number of recent block ids to cache for [nonce](zkvm-spec.md#nonce) uniqueness.

Output:
- [Blockchain state](#blockchain-state).

Procedure:
1. [Make an initial block](#make-initial-block) `initialblock` from `timestampms` and `refscount`.
2. Return a blockchain state with its fields set as follows:
   - `initialheader`: `initialblock.header`
   - `tipheader`: `initialblock.header`
   - `utxos`: empty set
   - `nonces`: empty set
   - `refids`: empty set

## Make initial block

Inputs:
- `timestampms`, the current time as a number of milliseconds since the Unix epoch:
  00:00:00 UTC Jan 1,
  1970.
- `refscount`, the number of recent block ids to cache for [nonce](zkvm-spec.md#nonce) uniqueness.

Output:
- a [block](#block).

Procedure:
1. Compute `txroot`, the root hash of an empty [Merkle binary tree](zkvm-spec.md#merkle-binary-tree) with label `transactions`.
2. Compute `utxoroot`, the root hash of an empty [Merkle patricia tree](#merkle-patricia-tree) with label `utxos`.
3. Compute `nonceroot`, the root hash of an empty [Merkle patricia tree](#merkle-patricia-tree) with label `nonces`.
4. Compute `header`, a [block header](#block-header) with its fields set as follows:
   - `version`: 1
   - `height`: 1
   - `previd`: all-zero string of 32-bytes
   - `timestampms`: `timestampms`
   - `txroot`: `txroot`
   - `utxoroot`: `utxoroot`
   - `nonceroot`: `nonceroot`
   - `refscount`: `refscount`
5. Return a block with `header` set to `header` and an empty `txs` list.

## Join existing network



## Validate block

Inputs:
- `block`,
  the block to validate.
- `prevheader`,
  the header of the previous block.

Output:
- list of
  [transaction logs](zkvm-spec.md#transaction-log),
  one for each transaction in block.txs.

Procedure:
1. Verify `block.header.version >= prevheader.version`.
2. Verify `block.header.height == prevheader.height+1`.
3. Verify `block.header.previd` equals the
   [block ID](#block-id)
   of `prevheader`.
4. Verify `block.header.timestampms > prevheader.timestampms`.
5. Verify `block.header.refscount >= 0` and `block.header.refscount <= prevheader.refscount + 1`.
5. For each transaction `tx` in block.txs:
   1. Verify `tx.mintimems == 0` or `tx.mintimems >= block.header.timestampms`.
   2. Verify `tx.maxtimems == 0` or `tx.maxtimems < block.header.timestampms`.
   3. If `block.header.version == 1`,
      verify `tx.version == 1`.
   4. [Execute](zkvm-spec.md#vm-execution)
      `tx` to produce transaction log `txlog`.
   5. Add `txlog` to the list of output logs.

## Apply block

Inputs:
- `block`,
  the block to apply.
- `state`,
  the current
  [blockchain state](#blockchain-state).

Output:
- New blockchain state.

Procedure:
1. [Validate](#validate-block)
   `block` with `prevheader` set to `state.tipheader`.
2. Let `state′` be `state`.
3. Remove items from `state′.nonces` where the expiration timestamp is less than `block.header.timestampms`.
4. For each txlog from the validation step,
   in order:
   1. [Apply](#apply-transaction-log)
      the txlog to `state′` to produce `state′′`.
   2. Set `state′ <- state′′`.
5. Compute `utxoroot` from `state′.utxos`.
6. Verify `block.header.utxoroot == utxoroot`.
7. Compute `nonceroot` from `state′.nonces`.
8. Verify `block.header.nonceroot == nonceroot`.
9. Set `state′.tipheader <- block.header`.
10. Add `block.header` to the end of the `state′.refids` list.
11. Prune `state′.refids` to the number of items specified by `block.header.refscount` by removing the oldest IDs.
12. Return `state′`.

## Apply transaction log

Inputs:
- `txlog`,
  a
  [transaction log](zkvm-spec.md#transaction-log).
- `state`,
  a
  [blockchain state](#blockchain-state).

Output:
- New blockchain state.

Procedure:
1. Let `state′` be `state`.
2. For each
   [nonce entry](zkvm-spec.md#nonce-entry)
   `n` in `txlog`:
   1. Verify `n.blockid` is one of the following:
      - An all-zero 32-byte string,
        or
      - The ID of the initial block,
        or
      - One of the block ids in `state.refids`.
   2. Verify `n` is _not_ in `state.nonces`.
   3. Add `n` to `state′.nonces`.
3. For each
   [input entry](zkvm-spec.md#input-entry)
   or
   [output entry](zkvm-spec.md#output-entry)
   in `txlog`:
   1. If an input entry,
      remove its utxo ID from `state′.utxos`.
   2. If an output entry,
      add its utxo ID to `state′.utxos`.
