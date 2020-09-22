# Slingshot API

Responses are listed in JSON for a time being, but we are also going to provide the API responses via XDR format.

## /v1/status

#### Request

`GET /v1/status`

#### Response

```json
{
    mempool: {
        count: 10571,    # number of transactions
        size: 57102452,  # total size of all transactions
        feerate: 123123, # lowest feerate for inclusion in the block
    },
    state: {
        height: 5103,                # latest block's number
        last_block: "1c61b3ff49...", # latest block's ID
        utreexo: [                   # utreexo merkle roots
            "4bdf5b3f981...",
            null,
            "8043b5f7842...",
            "6b6abc684a1..."
        ]
    },
    peers: [
        {
            id: "f7842641554...",       # pubkey of the peer
            since: 168401244121,        # Unix timestamp of the connection
            addr: "195.32.52.12:52930", # address of the peer
            priority: 123,              # priority of the peer (TBD: format/range)
        },
        ...
    ]
}
```

## /v1/mempool

#### Request

`GET /v1/mempool?[cursor=571]`

* `cursor`: opaque identifier to continue paginated request for transactions

#### Response

```json
{
    cursor: "571",  # use this opaque value to request the next set of transactions
    txs: [
        {
            txid: "f7842641554...",
            size: 2041,
            fee: 6913,
            raw: 
        }
    ]
}
```

## /v1/blocks

#### Request

`GET /v1/blocks?[cursor=571]`

* `cursor`: opaque identifier to continue paginated request for blocks

#### Response

```json
{
    cursor: "571",  # use this opaque value to request the next set of blocks
    blocks: [
        {
            height:    1242,
            timestamp: 1684910232,
            id:        "f7842641554...",
            size:      2041,
            fee:       6913,
            txs:       123,
        }
    ]
}
```


## /v1/block

Requests details of the given block.

#### Request

`GET /v1/block/<id>`

* `id`: hex-encoded block ID

#### Response

```json
{
    id:        "f7842641554...",
    height:    1242,
    timestamp: 1684910232,
    size:      2041,
    ...,          # TBD: other header data
    txs: [
        {
            id:   "f7842641554...",
            size: 1234,
            fee:  5491,
            
        }
    ]
}
```



## /v1/tx

Requests details for a given transactions. Looks for txs in blocks and in mempool.

#### Request

`GET /v1/tx/<txid>`

* `txid`: hex-encoded transaction ID

#### Response

```json
{
    status: {
        confirmed: true,            # false if in mempool
        block_height: 1234,
        block_id: "f7842641554..."
    },
    raw: "51fa8d9e0b0ad91921...",
    # TBD: friendly description of entries
}
```

## /v1/wallet/new

Creates a new wallet

#### Request

`POST /v1/wallet/new`

```json
{
    xpub: "68a9f6a8d903461231...",
    label: "My Wallet"
}
```

#### Response

```json
{
    status: "ok",
    id: "36812382",
}
```


## /v1/wallet/:id/balance

Returns wallet's balance.

#### Request

GET /v1/wallet/:id/balance

#### Response

```json
TBD.
```



## /v1/wallet/:id/txs

Lists annotated transactions.

#### Request

`GET /v1/wallet/:id/txs`

#### Response

```json
TBD.
```


## /v1/wallet/:id/build_tx

Builds a transaction

#### Request

`POST /v1/wallet/<wallet_id>/`

#### Response

TBD.
