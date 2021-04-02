# Slingshot API

* [Schema](#schema)
    * [MempoolStatus](#mempoolstatus)
    * [State](#state)
    * [Peer](#peer)
    * [BlockHeader](#blockheader)
    * [Block](#block)
    * [TxHeader](#txheader)
    * [RawTx](#rawtx)
    * [Tx](#tx)
    * [AnnotatedAction](#annotatedaction)
    * [AnnotatedTx](#annotatedtx)
* [Network API](#network-api)
    * [/network/status](#networkstatus)
    * [/network/mempool](#networkmempool)
    * [/network/blocks](#networkblocks)
    * [/network/block/:id](#networkblockid)
    * [/network/tx/:id](#networktxid)
* [Wallet API](#wallet-api)
    * [/wallet/new](#walletnew)
    * [/wallet/balance](#walletbalance)
    * [/wallet/txs](#wallettxs)
    * [/wallet/address](#walletaddress)
    * [/wallet/receiver](#walletreceiver)
    * [/wallet/buildtx](#walletbuildtx)


Responses are listed in JSON for a time being, but we are also going to provide the API responses via XDR format.

All URLs start with a versioned based path. So the full URL for the endpoint `/network/status` is `https://<hostname>/v1/network/status`

## Schema

### MempoolStatus

Stats about unconfirmed transactions.

```rust
struct MempoolStatus {
    count: u64,   // total number of transactions
    size: u64,    // total size of all transactions in the mempool
    feerate: u64, // lowest feerate for inclusing in the block
}
```

### State

Description of the current blockchain state.

```rust
struct State {
    tip: BlockHeader, // block header
    utreexo: [Option<[u8; 32]>; 64] // the utreexo state
}
```

### Peer

Description of a connected peer.

```rust
struct Peer {
    id: [u8; 32],
    since: u64,
    addr: [u8; 16], // ipv6 address format
    priority: u64,
}
```

### BlockHeader

```rust
struct BlockHeader {
    version: u64,      // Network version.
    height: u64,       // Serial number of the block, starting with 1.
    prev: [u8; 32], // ID of the previous block. Initial block uses the all-zero string.
    timestamp_ms: u64, // Integer timestamp of the block in milliseconds since the Unix epoch
    txroot: [u8; 32],   // 32-byte Merkle root of the transaction witness hashes (`BlockTx::witness_hash`) in the block.
    utxoroot: [u8; 32], // 32-byte Merkle root of the Utreexo state.
    ext: Vec<u8>,       // Extra data for the future extensions.
}
```

### Block

```rust
struct Block {
    header: BlockHeader,
    txs: Vec<Transaction>
}
```

### TxHeader

```rust
struct TxHeader {
    version: u64,     // Minimum network version supported by tx
    mintime_ms: u64,  // Minimum valid timestamp for the block
    maxtime_ms: u64,  // Maximum valid timestamp for the block
}
```

### RawTx

```rust
struct RawTx {
    header: TxHeader,
    program: Vec<u8>,
    signature: [u8; 64],
    r1cs_proof: Vec<u8>,
    utreexo_proofs: Vec<Vec<u8>>,
}
```

### Tx

```rust
struct Tx {
    id: [u8; 32],     // canonical tx id
    wid: [u8; 32],    // witness hash of the tx (includes signatures and proofs)
    raw: RawTx,
    fee: u64,         // fee paid by the tx
    size: u64,        // size in bytes of the encoded tx
}
```

### AnnotatedAction

```rust
enum AnnotatedAction {
    Issue(IssueAction),
    Spend(SpendAction),
    Receive(ReceiveAction),
    Retire(RetireAction),
    Memo(MemoAction),
}

struct IssueAction {
    entry: u32, // index of the txlog entry
    qty: u64,
    flv: [u8; 32],
}

struct SpendAction {
    entry: u32, // index of the txlog entry
    qty: u64,
    flv: [u8; 32],
    account: [u8; 32], // identifier of the account sending funds
}

struct ReceiveAction {
    entry: u32, // index of the txlog entry
    qty: u64,
    flv: [u8; 32],
    account: Option<[u8; 32]>, // identifier of the account receiving funds (if known)
}

struct RetireAction {
    entry: u32, // index of the txlog entry
    qty: u64,
    flv: [u8; 32],
}

struct MemoAction {
    entry: u32,
    data: Vec<u8>,
}
```

### AnnotatedTx

Annotated tx produced by the wallet API.

```rust
struct AnnotatedTx {
    tx: Tx, // raw tx
    actions: Vec<AnnotatedAction>
}
```

### BuildTxAction

```rust
enum BuildTxAction {
    IssueToAddress([u8; 32], u64, String),
    IssueToReceiver(Receiver),
    TransferToAddress([u8; 32], u64, String),
    TransferToReceiver(Receiver),
    Memo(Vec<u8>),
}
```


## Network API

### /network/status

Request:

`GET /network/status`

Response:

```rust
struct Status {
    mempool: MempoolStatus,
    state: State,
    peers: Vec<Peer>
}
```

### /network/mempool

Request:

`GET /network/mempool?[cursor=571]`

* `cursor`: opaque identifier to continue paginated request for transactions

Response:

```rust
struct MempoolTxs {
    cursor: Vec<u8>,
    status: MempoolStatus,
    txs: Vec<Tx>
}
```

### /network/blocks

Request:

`GET /network/blocks?[cursor=571]`

* `cursor`: opaque identifier to continue paginated request for blocks

Response:

```rust
struct Blocks {
    cursor: Vec<u8>,
    blocks: Vec<BlockHeader>,
}
```


### /network/block/:id

Request

`GET /network/block/:id`

* `id`: hex-encoded block ID

Response:

```rust
struct Block {
    ... // see definition above
}
```

### /network/tx/:id

Requests details for a given transactions. Looks for txs in blocks and in mempool.

Request:

`GET /network/tx/:id`

* `id`: hex-encoded transaction ID

Response:

```rust
struct TxResponse {
    status: TxStatus,
    tx: Tx,
}

struct TxStatus {
    confirmed: bool,
    block_height: u64,
    block_id: [u8; 32],
} 
```

### /network/submit

Submits a fully-formed transaction. Successful submission returns 200 OK status.

Request:

`POST /network/submit`

```rust
struct RawTx {
    ... // see definition above
}
```





## Wallet API

Wallet is an abstraction that translates high-level operations such as issuances and transfers into deriving keys, 
forming transactions and tracking the state of unspent outputs.

### /wallet/new

Creates a new wallet. Successful submission returns 200 OK status.

Request:

`POST /wallet/new`

```rust
struct NewWalletRequest {
    xpub: [u8; 64],
    label: String,
}
```

### /wallet/balance

Returns wallet's balance.

Request:

`GET /wallet/balance`

Response:

```rust
struct Balance {
    balances: Vec<([u8; 32], u64)>
}
```


### /wallet/txs

Lists annotated transactions.

Request:

`GET /wallet/txs?cursor=[5786...]`

Response:

```rust
struct WalletTxs {
    cursor: Vec<u8>,
    txs: Vec<AnnotatedTx>
}
```

### /wallet/address

Generates a new address.

Request:

`GET /wallet/address`

Response:

```rust
struct NewAddress {
    address: String,
}
```

### /wallet/receiver

Generates a new receiver.

Request:

`POST /wallet/receiver`

```rust
struct NewReceiverRequest {
    flv: [u8; 32],
    qty: u64,
    exp: u64, // expiration timestamp
}
```

Response:

```rust
struct NewReceiverResponse {
    receiver: Receiver,
}
```

### /wallet/buildtx

Builds a transaction and returns the signing instructions.

Request:

`POST /wallet/buildtx`

```rust
struct BuildTxRequest {
    actions: Vec<BuildTxAction>,
}
```

Response:

```rust
struct BuiltTx {
    tx: AnnotatedTx,
    signing_instructions: Vec<SigningInstructions>
}
```
