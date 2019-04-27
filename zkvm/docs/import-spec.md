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





## Peg in specification

This is a multi-step process that requires actions from
both the user and the custodian who secures the peg.

#### Preparation step

The user prepares an input on the ZkVM chain, the [contract ID](zkvm-spec.md#contract-id) of which
will be a unique anchor for the [issuance contract](zkvm-spec.md#issue) for the imported funds.

This step requires no cooperation from the custodian.

TBD: this can be extended to support multiple assets imported under one predicate for certain multi-asset contracts.

#### Deposit step

TBD: user makes a payment with a well-formed memo field to the custodian's address.

#### Import step

TBD. 

Custodian-signer receives two pieces of data:

1. A proof of a stellar deposit: a transaction, a proof of publication in the chain, and externalized SCP message trusted by the custodian.
2. Components of the issuance to be signed on the ZkVM: check the anchor ID specified in the memo field, compose metadata based on [flavor id mapping rule](#flavor-id-mapping), form qty commitment.

Signs the program from the memo field, and the computed contract ID for a given asset, and returns the signature.

User receives the signature, uses it in their zkvm transaction, and satisfies the signed program with the user's signature. The asset is moved/split how the user wishes.



TBD: should we automagically make tx on ZkVM, or simply return signed blob to the user to perform tx themselves?
The latter is working better with utxo proofs, and makes less moves on the network, but requires extra actions from the user.
However, user needs to create a token anyway, so these operations can all be turned around quickly within one session (also unconfirmed txs can be chained).




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
