# ZkVM blockchain specification

This is the specification for the ZkVM blockchain,
a blockchain containing [ZkVM transactions](zkvm-spec.md).

# Blockchain state

The blockchain state contains:

- `initialheader`: The initial block header (at height 1).
- `tipheader`: The latest block header.
- `utxos`: The IDs of all available [utxos](zkvm-spec.md#utxo).

# Block header

A block header contains:

- `version`: integer version number, set to 1.
- `height`: integer block height. Initial block has height 1. Height increases by 1 with each new block.
- `previd`: ID of the preceding block. For the initial block (which has no predecessor), an all-zero string of 32 bytes.
- `timestamp`: integer timestamp of the block in milliseconds since the Unix epoch: 00:00:00 UTC Jan 1, 1970.
  Each new block must have a time strictly later than the block before it.
- `txroot`: 32-byte merkle root hash of the transactions in the block.
- `utxoroot`: 32-byte merkle root hash of the utxo set after applying all transactions in the block.

# Block

A block contains:

- `header`: a [block header](#block-header).
- `txs`: a list of [transactions](zkvm-spec.md#transaction).

# Block ID

A block ID is computed from a [block header](#block-header) using the [transcript](zkvm-spec.md#transcript) mechanism:

```
T = Transcript("ZkVM.blockheader")
T.commit(LE64(version))
T.commit(LE64(height))
T.commit(previd)
T.commit(LE64(timestamp))
T.commit(txroot)
T.commit(utxoroot)
blockid = T.challenge_bytes("id")
```

# Make initial block

# Join network

# Validate block

Inputs:
- `block`, the block to validate.
- `prevheader`, the header of the previous block.

Output:
- list of [txlog](zkvm-spec.md#transaction-log)+[txid](zkvm-spec.md#transaction-id) pairs,
  one for each transaction in block.txs.

Procedure:
1. Verify `block.header.version >= prevheader.version`.
2. Verify `block.header.height == prevheader.height+1`.
3. Verify `block.header.previd` equals the [block ID](#block-id) of `prevheader`.
4. Verify `block.header.timestamp > prevheader.timestamp`.
5. For each transaction `tx` in block.txs:
   1. Verify `tx.mintime == 0` or `tx.mintime >= block.header.timestamp`.
   2. Verify `tx.maxtime == 0` or `tx.maxtime < block.header.timestamp`.
   3. If `block.header.version == 1`, verify `tx.version == 1`.
   4. [Execute](zkvm-spec.md#vm-execution) `tx` to produce transaction log `txlog`.
   5. Compute [transaction ID](zkvm-spec.md#transaction-id) `txid` from `tx` and `txlog`.
   6. Add the pair `txlog`+`txid` to the list of output pairs.

# Apply block

Inputs:
- `block`, the block to apply.
- `state`, the current [blockchain state](#blockchain-state).

Output:
- New blockchain state.

Procedure:
1. [Validate](#validate-block) `block` with `prevheader` set to `state.tipheader`.
2. Let `state′` be `state`.
3. For each txlog from the validation step, in order:
   1. [Apply](#apply-transaction-log) the txlog to `state′` to produce `state′′`.
   2. xxx error check
   3. Set `state′ <- state′′`.
4. Compute `utxoroot` from `state′.utxos`.
5. Verify `block.header.utxoroot == utxoroot`.
6. Set `state′.tipheader <- block.header`.
7. Return `state′`.

# Apply transaction

Inputs:
- `txlog`, a [transaction log](zkvm-spec.md#transaction-log).
- `state`, a [blockchain state](#blockchain-state).

Output:
- New blockchain state.

Procedure:
- 