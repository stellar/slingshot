# Importing assets from Stellar to ZkVM

This protocol defines the process of importing of assets originally issued on the Stellar into ZkVM and exporting them back to the Stellar network.

The assets may change hands and another user may export the asset back, than the user who imported them in the first place.

The protocol uses _trusted custodian_ secured with multi-signatures and stateless validation (participants rely on validity of the blockchain state instead of the private state of the custodian, plus their honest ).

* [Definitions](#definitions)
* [Peg-in specification](#peg-in-specification)
* [Peg-out specification](#peg-out-specification)
* [Flavor ID mapping](#flavor-id-mapping)

## Definitions

### Main chain

The Stellar chain where the assets are originally issued.

### Side chain

The ZkVM chain where the [original asset](#original-asset) is represented by the [mapped asset](#mapped-asset) issued by [custodian](#custodian).

### Original asset

An asset originally issued on the [main chain](#main-chain).

### Mapped asset

An asset issued on the [side chain](#side-chain) with an intent to represent a corresponding [original asset](#original-asset) implementing a [peg](#peg).

### User

A party that controls an [original asset](#original-asset) and wishes to [peg](#peg) it to the [side chain](#side-chain) in order to perform trades using it there. 

### Custodian

A party that is trusted to hold 1:1 balance between the [deposited](#deposit) assets on the [main chain](#main-chain)
and the [imported](#import) assets on the [side chain](#side-chain).

### Custodian-signer

A component of the [custodian](#custodian) that performs a signing protocol for [import](#import) or [withdrawal](#withdrawal).

### Custodian-node

A component of the [custodian](#custodian) that performs service functions such as
locating [deposits](#deposit) and [exports](#export), building transactions and
routing data to the [custodian-signer](#custodian-signer).

### Peg

The property of an [original asset](#original-asset) to be immobilized on the [main chain](#main-chain) (with the support of [custodian](#custodian)),
while being represented with a [mapped asset](#mapped-asset) on the [side chain](#side-chain).

Assets can be [pegged in](#peg-in) an [pegged out](#peg-out).

### Peg in

A combination of [deposit](#deposit) and [import](#import) actions resulting in a [peg](#peg).

### Peg out

A combination of [export](#export) and [withdrawal](#withdrawal) actions that undo the [peg](#peg) for a given asset.

### Deposit

Transfer of an [original asset](#original-asset) by [user](#user) to the [custodian](#custodian) on the [main chain](#main-chain),
which is followed by an [import](#import) action.

### Withdrawal

Transfer of an [original asset](#original-asset) from the [custodian](#custodian) to a [user](#user) on the [main chain](#main-chain),
following an [export](#export) action.

### Import

Issuance of the [mapped asset](#mapped-asset) by the [custodian](#custodian) followed by the [deposit](#deposit).

### Export

Retirement of the [mapped asset](#mapped-asset) by the [user](#user) in order to perform [withdrawal](#withdrawal).



## Setup

Custodian is initialized with a multi-signature account that [pegs](#peg) all the received funds.


## Peg in specification

This is a multi-step process that requires actions from
both the user and the custodian who secures the peg.

#### Preparation step

The user prepares an unspent output on the ZkVM chain, the [contract ID](zkvm-spec.md#contract-id) of which
will be a unique anchor for the [issuance contract](zkvm-spec.md#issue) for the imported funds.
This output can be specifically created for the purpose of this protocol,
or simply locked within the user’s wallet to not be accidentally spent by other transaction.

User also prepares a program to be signed by the [custodian](#custodian) which allows user to authorize spending of the [mapped asset](#mapped-asset).

The program can be anything. The simplest option is to lock the [mapped asset](#mapped-asset) by the user’s public key,
then the user can author any transaction spending this asset themselves.

```
push:<pubkey> contract:1
```

#### Deposit step

User forms a transaction paying to the custodian’s account N units of asset A, with a memo string of type `MEMO_HASH` the identifies the [import](#import) on the ZkVM chain.

The memo is a 32-byte hash computed as follows:

```
T = Transcript::new("ZkVM.import")
T.commit("program", program)  // user’s authorization program to be signed by the custodian
T.commit("anchor", anchor)    // contract ID to be used as an anchor in the issuance contract
memo = T.challenge_bytes()
```

User signs and publishes the [deposit](#deposit) transaction.

#### Signing step

Once the [deposit](#deposit) transaction is published, user and [custodian-signer](#custodian-signer) perform the following stateless protocol:

First, user sends a reference to the deposit transaction, `program` and `anchor`.

In response, custodian-signer:

1. Takes the first payment, ignores the rest and reads `Asset` structure and the paid quantity.
2. Verifies that the `MEMO_HASH` matches the `program` and `anchor` specified by the user (see above).
3. Computes an unblinded `qty` commitment based on the quantity.
4. Forms a metadata string for the `issue` instruction as XDR encoding of the `Asset` structure. See [Flavor ID mapping](#flavor-id-mapping).
5. Computes the ZkVM [flavor ID](zkvm-spec.md#issue) using its ZkVM issuance predicate and the metadata string. This defines the flavor ID for the [mapped asset](#mapped-asset).
6. Creates a contract with the `anchor`, issuance predicate and the Value object with unblinded quantity and flavor commitments.
7. Computes the [contract ID](zkvm-spec.md#contract-id) of the resulting contract.
8. Signs user’s `program` and the issuance contract ID for the [`delegate`](zkvm-spec.md#delegate) instruction.
9. Returns the signature to the user.

Note: this protocol can be safely replayed arbitrary number of times because both the Stellar payment
is tied to the same unique anchor (embedded in a `MEMO_HASH`) as the ZkVM signature for the delegate instruction
(which covers the issuance contract that uses the anchor).

Future work: 

1. this can be extended to support multiple assets imported under one predicate for certain multi-asset contracts.
2. multiple payments to the custodian can also be supported and not be ignored.

#### Import step

User forms a transaction that spends the previously allocated unspent output, followed by the following issuance snippet:

```
<utxo> input
<Q> <F> <XDR(Asset)> <issuance_predicate> issue
<user_prog> <signature> delegate
...
```

where:

* `utxo` is the serialized UTXO that the user is spending, and which contract ID is used as an anchor in the issuance contract.
* `Q` is an unblinded quantity commitment.
* `F` is an unblinded flavor commitment.
* `XDR(Asset)` is metadata string — XDR-serialized `Asset` structure describing the [original asset](#original-asset) type.
* `issuance_predicate` is the custodian’s issuance predicate for which the `signature` is provided.
* `user_prog` is the user-provided authorization program embedded into `MEMO_HASH` on the [main chain](#main-chain).
* `signature` is the custodian-signer’s signature corresponding to the `issuance_predicate`.

TBD: a sketch of what user needs to do to allow non-interactive issuance.

## Peg out specification

TBD: 

Sketch: 

Prepare a unique account (starting seq num is the ledger's seqno), and pre-determined transaction that merges it back in,
perform export/retire, ask signer to sign that tx that pays to a destination address and also merges that account.

The signer has to check that tx they are signing has that one merge operation which guarantees replay prevention (simply sequence number won't do as it can be updated with other requests). It should be possible to batch concurrent withdrawals in one tx, that has multiple pairs of (pay-out, unique-acc-merge) operations corresponding to the respective exports in zkvm.


## Flavor ID mapping

To map the Stellar asset into ZkVM flavor, we will use `metadata` argument that represents an XDR-encoded `Asset` structure
as specified in the `Stellar-ledger-entries.x` XDR file:

```
namespace stellar {
	typedef PublicKey AccountID;
	...
	typedef opaque AssetCode4[4];
	typedef opaque AssetCode12[12];

	enum AssetType {
	    ASSET_TYPE_NATIVE = 0,
	    ASSET_TYPE_CREDIT_ALPHANUM4 = 1,
	    ASSET_TYPE_CREDIT_ALPHANUM12 = 2
	};

	union Asset switch (AssetType type) {
		case ASSET_TYPE_NATIVE: void;
		case ASSET_TYPE_CREDIT_ALPHANUM4:
		    struct {
		        AssetCode4 assetCode;
		        AccountID issuer;
		    } alphaNum4;
		case ASSET_TYPE_CREDIT_ALPHANUM12:
		    struct {
		        AssetCode12 assetCode;
		        AccountID issuer;
		    } alphaNum12;
	};
}
```

The resulting _flavor scalar_ is therefore formed as any other flavor, as a combination of the ZkVM issuer (custodian) key and the metadata identifying the Stellar asset.

See also [ZkVM `issue` documentation](zkvm-spec.md#issue).
