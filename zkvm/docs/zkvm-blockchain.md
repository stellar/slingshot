# ZkVM blockchain specification

This is the specification for the ZkVM blockchain,
a blockchain containing
[ZkVM transactions](zkvm-spec.md).

Nodes participating in a ZkVM blockchain network must implement the data types and perform the procedures described in this document.
Specifically:

- Each node maintains a [blockchain state](#blockchain-state).
- A node creating a new ZkVM network performs the [start new network](#start-new-network) procedure.
- A node joining an existing ZkVM network performs the [join existing network](#join-existing-network) procedure.
- Each node performs the [apply block](#apply-block) procedure on the arrival of each new block.

This document does not describe the mechanism for producing blocks from pending transactions,
nor for choosing among competing blocks to include in the authoritative chain
(a.k.a. consensus).

_TBD: add a consensus spec._

# Data types

## Blockchain state

The state of a ZkVM blockchain is given by the blockchain-state structure.
Each node maintains a copy of this structure.
As each new [block](#block) arrives,
it is [applied](#apply-block) to the current state to produce a new,
updated state.

The blockchain state contains:

- `initialheader`: The initial block header
  (the header with height 1).
  This never changes.
- `tipheader`: The latest block header.
- `utxos`: The list of current [utxo IDs](zkvm-spec.md#utxo).

## Block

A block contains:

- `header`: A [block header](#block-header).
- `txs`: A list of [transactions](zkvm-spec.md#transaction).

The initial block
(at height 1)
has an empty list of transactions.

## Block header

A block header contains:

- `version`: Integer version number,
  set to 1.
- `height`: Integer block height.
  Initial block has height 1.
  Height increases by 1 with each new block.
- `previd`: ID of the preceding block.
  For the initial block
  (which has no predecessor),
  this is an all-zero string of 32 bytes.
- `timestamp_ms`: Integer timestamp of the block in milliseconds since the Unix epoch:
  00:00:00 UTC Jan 1, 1970.
  Each new block must have a time strictly later than the block before it.
- `txroot`: 32-byte [Merkle root hash](zkvm-spec.md#merkle-binary-tree) of the transactions in the block.
- `utxoroot`: 32-byte [Merkle root hash](zkvm-spec.md#merkle-binary-tree) of the utxo set after applying all transactions in the block.
- `ext`: Variable-length byte string to contain future extensions.
  Empty in version 1.

## Block ID

A block ID is computed from a [block header](#block-header) using the [transcript](zkvm-spec.md#transcript) mechanism:

```
T = Transcript("ZkVM.blockheader")
T.commit("version", LE64(version))
T.commit("height", LE64(height))
T.commit("previd", previd)
T.commit("timestamp_ms", LE64(timestamp_ms))
T.commit("txroot", txroot)
T.commit("utxoroot", utxoroot)
T.commit("ext", ext)
blockid = T.challenge_bytes("id")
```


# Procedures

In the descriptions that follow,
the word “verify” means to test whether a condition is true.
If it’s false,
all pending procedures abort and a failure result is returned.

## Start new network

A node starts here when creating a new blockchain network.
Its [blockchain state](#blockchain-state) is set to the result of the procedure.

Inputs:
- `timestamp_ms`,
  the current time as a number of milliseconds since the Unix epoch: 00:00:00 UTC Jan 1, 1970.
- `utxos`,
  the starting utxo set that allows bootstrapping the anchors.

Output:
- Blockchain state.

Procedure:
1. [Make an initial block header](#make-initial-block-header) `initialheader` from `timestamp_ms` and `utxos`.
2. Return a blockchain state with its fields set as follows:
   - `initialheader`: `initialheader`
   - `tipheader`: `initialheader`
   - `utxos`: `utxos`

## Make initial block header

Inputs:
- `timestamp_ms`,
  the current time as a number of milliseconds since the Unix epoch: 00:00:00 UTC Jan 1, 1970.
- `utxos`,
  the initial list of [utxo IDs](zkvm-spec.md#utxo) needed to bootstrap [ZkVM anchors](zkvm-spec.md#anchor).


Output:
- A [block header](#block-header).

Procedure:
1. [Compute txroot](#compute-txroot) from an empty list of transaction ids.
2. [Compute utxoroot](#compute-utxoroot) from `utxos`.
3. Return a [block header](#block-header) with its fields set as follows:
   - `version`: 1
   - `height`: 1
   - `previd`: all-zero string of 32-bytes
   - `timestamp_ms`: `timestamp_ms`
   - `txroot`: `txroot`
   - `utxoroot`: `utxoroot`
   - `ext`: empty

## Join existing network

A new node starts here when joining a running network.
It must either:
- obtain all historical blocks,
  [applying](#apply-block) them one by one to reproduce the latest [blockchain state](#blockchain-state);
  or
- obtain a recent copy of the blockchain state `state` from a trusted source
  (e.g., another node that has already validated the full history of the blockchain)
  and begin applying blocks beginning at `state.tipheader.height+1`.

An obtained (as opposed to computed) blockchain state `state` may be partially validated by [computing the utxoroot](#compute-utxoroot) from `state.utxos` and verifying that it equals `state.header.utxoroot`.


## Validate block

Validating a block checks it for correctness outside the context of a particular [blockchain state](#blockchain-state).

Additional correctness checks against a particular blockchain state happen during the [apply block](#apply-block) procedure,
of which this is a subroutine.

Inputs:
- `block`,
  the block to validate,
  at height 2 or above.
- `prevheader`,
  the previous blockheader.

Output:
- list of [transaction logs](zkvm-spec.md#transaction-log),
  one for each transaction in block.txs.

Procedure:
1. Verify `block.header.version >= prevheader.version`.
2. If `block.header.version == 1`, verify `block.header.ext` is empty.
3. Verify `block.header.height == prevheader.height+1`.
4. Verify `block.header.previd` equals the [block ID](#block-id) of `prevheader`.
5. Verify `block.header.timestamp_ms > prevheader.timestamp_ms`.
6. Let `txlogs` and `txids` be the result of [executing the transactions in block.txs](#execute-transaction-list) with `block.header.version` and `block.header.timestamp_ms`.
7. [Compute txroot](#compute-txroot) from `txids`.
8. Verify `txroot == block.header.txroot`.
9. Return `txlogs`.


## Make block

Inputs:
- `state`,
  a [blockchain state](#blockchain-state).
- `version`,
  a version number for the new block.
  Note that this must be equal to or greater than `state.tipheader.version`,
  the version number of the previous block header.
- `timestamp_ms`,
  a time for the new block as milliseconds since the Unix epoch,
  00:00:00 UTC Jan 1, 1970.
  This must be strictly greater than `state.tipheader.timestamp_ms`,
  the timestamp of the previous block header.
- `txs`,
  a list of [transactions](zkvm-spec.md#transaction).
- `ext`,
  the contents of the new block’s “extension” field.
  Note that at this writing,
  only block version 1 is defined,
  which requires `ext` to be empty.

Output:
- a new [block](#block) containing `txs`.

Procedure:
1. Let `previd` be the [block ID](#block-id) of `state.tipheader`.
2. Let `txlogs` and `txids` be the result of [executing txs](#execute-transaction-list) with `version` and `timestamp_ms`.
3. Let `state´` be the result of [applying txlogs](#apply-transaction-list) to `state`.
4. Let `txids` be the list of [transaction IDs](zkvm-spec.md#transaction-id) of the transactions in `txs`,
   computed from each transaction’s [header entry](zkvm-spec.md#header-entry) and the corresponding item from `txlogs`.
5. [Compute txroot](#compute-txroot) from `txids` to produce `txroot`.
6. [Compute utxoroot](#compute-utxoroot) from `state′.utxos` to produce `utxoroot`.
7. Let `h` be a [block header](#block-header) with its fields set as follows:
   - `version`: `version`
   - `height`: `state.tipheader.height+1`
   - `previd`: `previd`
   - `timestamp_ms`: `timestamp_ms`
   - `txroot`: `txroot`
   - `utxoroot`: `utxoroot`
   - `ext`: `ext`
8. Return a block with header `h` and transactions `txs`.


## Execute transaction list

Input:
- `txs`,
  a list of [transactions](zkvm-spec.md#transaction).
- `version`,
  a version number for a block.
- `timestamp_ms`,
  a block timestamp as milliseconds since the Unix epoch,
  00:00:00 UTC Jan 1, 1970.

Outputs:
- a list of [transaction logs](zkvm-spec.md#transaction-log),
  one per transaction in `txs`.
- a list of [transaction IDs](zkvm-spec.md#transaction-id),
  one per transaction in `txs`.

Procedure:
1. Let `txlogs` be an empty list of transaction logs.
   Let `txids` be an empty list of transaction IDs.
2. For each transaction `tx` in `txs`:
   1. Verify `tx.mintime_ms <= timestamp_ms <= tx.maxtime_ms`.
   2. If `version == 1`, verify `tx.version == 1`.
   3. [Execute](zkvm-spec.md#vm-execution) `tx` to produce transaction log `txlog`.
   4. Add `txlog` to `txlogs`.
   5. Compute transaction ID `txid` from the [header entry](zkvm-spec.md#header-entry) of `tx` and from `txlog`.
   6. Add `txid` to `txids`.
3. Return `txlogs` and `txids`.

Note that step 2 can be parallelized across `txs`.


## Apply block

Applying a block causes a node to replace its [blockchain state](#blockchain-state) with the updated state that results.

Inputs:
- `block`,
  the [block](#block) to apply.
- `state`,
  the current blockchain state.

Output:
- New blockchain state `state′`.

Procedure:
1. Let `txlogs` be the result of [validating](#validate-block) `block` with `prevheader` set to `state.tipheader`.
2. Let `state′` be `state`.
3. Let `state′′` be the result of [applying txlogs](#apply-transaction-list) to `state′`.
4. Set `state′ <- state′′`.
5. [Compute utxoroot](#compute-utxoroot) from `state′.utxos`.
6. Verify `block.header.utxoroot == utxoroot`.
7. Set `state′.tipheader <- block.header`.
8. Return `state′`.


## Apply transaction list

Inputs:
- `state`,
  a [blockchain state](#blockchain-state).
- `txlogs`,
  a list of [transaction logs](zkvm-spec.md#transaction-log).

Output:
- Updated blockchain state.

Procedure:
1. Let `state′` be `state`.
2. For each `txlog` in `txlogs`,
   in order:
   1. Let `state′′` be the result of [applying the txlog](#apply-transaction-log) to `state′` to produce `state′′`.
   2. Set `state′` <- `state′′`.
3. Return `state′`.



## Apply transaction log

Inputs:
- `txlog`,
  a [transaction log](zkvm-spec.md#transaction-log).
- `state`,
  a [blockchain state](#blockchain-state).

Output:
- New blockchain state `state′`.

Procedure:
1. Let `state′` be `state`.
2. For each [input entry](zkvm-spec.md#input-entry) or [output entry](zkvm-spec.md#output-entry) in `txlog`:
   1. If an input entry,
      verify its ID is in `state′.utxos`,
      then remove it.
   2. If an output entry,
      append its utxo ID to `state′.utxos`.
3. Return `state′`.

## Compute txroot

Input:
- Ordered list `txids` of [transaction IDs](zkvm-spec.md#transaction-id).

Output:
- [Merkle root hash](zkvm-spec.md#merkle-binary-tree) of the transaction list.

Procedure:
1. Create a [transcript](zkvm-spec.md#transcript) `T` with label `transaction_ids`.
2. Return `MerkleHash(T, txids)` using the label `txid` for each transaction ID in the list.

## Compute utxoroot

Input:
- Ordered list `utxos` of [utxo IDs](zkvm-spec.md#utxo).

Output:
- [Merkle root hash](zkvm-spec.md#merkle-binary-tree) of the given utxos.

Procedure:
1. Create a [transcript](zkvm-spec.md#transcript) `T` with label `utxos`.
2. Return `MerkleHash(T, utxos)`.

