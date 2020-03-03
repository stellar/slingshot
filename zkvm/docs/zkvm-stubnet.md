# ZkVM stubnet protocol

This document describes the "stubnet" p2p communication protocol for ZkVM blockchain.

## Stubnet goal

It uses proper p2p transaction and block broadcast, but uses a single pre-determinate party to announce blocks (centralized block signer).

However, to make transition to decentralized consensus easier, nothing else in the protocol assumes the central party.
All peers are equal and signed block can originate from any node.

## Definitions

### Node

A member of the network that maintains a blockchain state and sends/receives [messages](#messages) to/from its [peers](#peer).

### Peer

Another [node](#node) that’s connected to your node.

### Inbound peer

A connection initiated by a [peer](#peer) to your [node](#node).

### Outbound peer

A connection initiated by your [node](#node) to a [peer](#peer).

### BlockchainTx

A transaction envelope format that contains pure ZkVM transaction and a list of Utreexo proofs.

### Block

A block envelope format that contains a BlockID and a list of [BlockchainTx](#blockchaintx) objects.


### Short ID

A 6-byte transaction ID, specified for a given _nonce_ (little-endian u64).

1. Initialize [SipHash-2-4](https://131002.net/siphash/) with k0 set to nonce, k1 set to the first 8 bytes as little-endian u64 of the recipient’s Peer ID.
2. Feed transaction ID as an input to SipHash.
3. Read u64 output, drop two most significant bytes.

See also [BIP-152](https://github.com/bitcoin/bips/blob/master/bip-0152.mediawiki).


## Protocol

Upon receiving an inbound connection, or making an outbound connection, a node sends [`GetInventory`](#getinventory) to the peer
with the same random nonce across all peers (so responses contain comparable [short IDs](#short-id)).

When receiving a [`GetInventory`](#getinventory) message, the peer is marked as "waiting for inventory".
Required delay allows avoiding resource exhaustion with repeated request and probing the state of the node.

When receiving an [`Inventory`](#inventory) message:

1. Peer's tip is remembered per-peer.
2. If the tip block header is higher than the current target one, it is verified and remembered as a new target one.
3. If the tip matches, the list of mempool transactions is remembered per-peer and filtered down against already present transactions, so it only contains transactions that the node does not have, but the peer does have.

Periodically (every 1-2 seconds):

1. The peers who requested inventory are sent a new [`Inventory`](#inventory) message.
2. **If the target tip does not match the current state,** the node requests missing blocks using [`GetBlocks`](#getblocks) from the peers evenly (e.g. 1 block from each peer).
3. **If the target tip is the latest**, the node walks all peers in round-robin and constructs lists of [short IDs](#short-id) to request from each peer, keeping track of already used IDs. Once all requests are constructed, the [`GetMempoolTxs`](#getmempooltxs) messages are sent out to respective peers.

When [`Blocks`](#blocks) message is received:
1. Direct descendant is verified and advances the state. Orphan blocks from other peers are tried to be applied.
2. Earlier blocks are discarded.
3. Orphan blocks are stored in a LRU buffer per peer.

When [`MempoolTxs`](#mempooltxs) message is received: if tip matches the current state, transactions are applied to the mempool.
Otherwise, the message is discarded as stale.


## Messages

### `GetInventory`

"Get inventory". Requests the state of the node: its blockchain state and transactions in the mempool.

```
struct GetInventory {
    version: u64,
    shortid_nonce: u64
}
```

### `Inventory`

Sends the inventory of a node back to the peer who requested it with [`GetInventory`](#getinventory) message. Contains the block tip and the contents of mempool as a list of [short IDs](#short-id).

```
struct Inventory {
    version: u64,
    tip_header: BlockHeader,
    stubnet_signature: starsig::Signature,
    mempool: Vec<ShortID>
}
```

### `GetBlocks`

Requests a list of blocks after a given tip. Specifies both the height and the ID for quick lookup and consistency check.

```
struct GetBlocks {
    tip: BlockID,
    height: u64,
}
```

### `Blocks`

Sends a list of blocks requested with [`GetBlocks`](#getblocks) message.

```
struct Blocks {
    blocks: Vec<Block>
}
```

### `GetMempoolTxs`

Requests a subset of mempool transactions with the given [short IDs](#short-id) after receiving the [`Inventory`](#inventory) message.

```
struct GetMempoolTxs {
    shortid_nonce: u64,
    shortids: Vec<ShortID>
}
```

### `MempoolTxs`

Sends a subset of mempool transactions in response to [`GetMempoolTxs`](#getmempooltxs) message.

The node sends a list of [blockchain transaction](#blockchaintx) packages matching the [short IDs](#short-id) requested.

```
struct MempoolTxs {
    tip: BlockID,
    txs: Vec<BlockchainTx>
}
```

