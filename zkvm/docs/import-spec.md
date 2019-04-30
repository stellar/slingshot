# Importing assets from Stellar to ZkVM

This protocol defines the process of importing of assets originally issued on the Stellar into ZkVM and exporting them back to the Stellar network.

The assets may change hands and another user may export the asset back, than the user who imported them in the first place.

The protocol uses _trusted custodian_ secured with multi-signatures and stateless validation (everyone relies only on validity of the blockchain state and honest execution of the stateless signers).

* [Definitions](#definitions)
* [Setup](#setup)
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

[Custodian](#custodian) is initialized with:

1. A multi-signature account on [main chain](#main-chain) that [pegs](#peg) all the received [original assets](#original-asset).
2. A multi-signature predicate on [side chain](#side-chain) that issues the [mapped assets](#mapped-asset).
3. A quorum slice configuration for each chain (main + side) which will be used to verify publication of the transaction.

[Users](#user) are assumed to know about the above configuration (e.g. it is built into the wallets),
and can derive all subsequent data such as [flavor IDs](#flavor-id-mapping).



## Peg in specification

This is a multi-step process that requires actions from
both the user and the custodian who secures the peg.

#### Preparation step

[User](#user) prepares an unspent output on the ZkVM chain, the [contract ID](zkvm-spec.md#contract-id) of which
will be a unique anchor for the [issuance contract](zkvm-spec.md#issue) for the imported funds.
This output can be specifically created for the purpose of this protocol,
or simply locked within the user’s wallet to not be accidentally spent by other transaction.

User also prepares a `program` to be signed by the [custodian](#custodian) which allows user to authorize spending of the [mapped asset](#mapped-asset).
The `program` can be anything. The simplest option is to lock the [mapped asset](#mapped-asset) by the user’s public key,
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
memo = T.challenge_bytes("memo")
```

User signs and publishes the [deposit](#deposit) transaction.

#### Signing step

Once the [deposit](#deposit) transaction is published, user and [custodian](#custodian) perform the following stateless protocol:

First, user sends a reference to the [deposit](#deposit) transaction, `program` and `anchor`.

In response, custodian:

1. [Custodian](#custodian) verifies that the deposit transaction is published (via hash-links to a ledger that’s signed by an externalized SCP message with quorum slice trusted by the custodian).
2. Takes the first payment, ignores the rest and reads `Asset` structure and the paid quantity.
3. Verifies that the `MEMO_HASH` matches the `program` and `anchor` specified by the user (see above).
4. Computes an unblinded `qty` commitment based on the quantity.
5. Forms a metadata string for the `issue` instruction as XDR encoding of the `Asset` structure. See [Flavor ID mapping](#flavor-id-mapping).
6. Computes the ZkVM [flavor ID](zkvm-spec.md#issue) using its ZkVM issuance predicate and the metadata string. This defines the flavor ID for the [mapped asset](#mapped-asset).
7. Creates a contract with the `anchor`, issuance predicate and the Value object with unblinded quantity and flavor commitments.
8. Computes the [contract ID](zkvm-spec.md#contract-id) of the resulting contract.
9. Signs user’s `program` and the issuance contract ID for the [`delegate`](zkvm-spec.md#delegate) instruction, producing `signature`.
10. Returns the `signature` to the user.

Note: this protocol can be safely replayed arbitrary number of times because both the Stellar deposit and ZkVM issuance
are tied to the same unique anchor (embedded in a `MEMO_HASH`) — the ZkVM signature for the `delegate` instruction covers the issuance contract, which in turn contains the anchor.

Future work:

1. this can be extended to support multiple assets imported under one predicate for certain multi-asset contracts.
2. multiple payments to the custodian in the same transaction can also be supported instead of being ignored.

#### Import step

User forms a transaction that spends the previously allocated unspent output, followed by the following issuance snippet:

```
push:<utxo>
input

push:<Q>
push:<F>
push:<XDR(Asset)>
push:<issuance_predicate>
issue

push:<user_prog>
push:<signature>
delegate
...
```

where:

* `utxo` is the serialized UTXO that the user is spending, and which contract ID is used as an anchor in the issuance contract.
* `Q` is an unblinded quantity commitment.
* `F` is an unblinded flavor commitment.
* `XDR(Asset)` is metadata string — XDR-serialized `Asset` structure describing the [original asset](#original-asset) type.
* `issuance_predicate` is the custodian’s issuance predicate for which the `signature` is provided.
* `user_prog` is the user-provided authorization program embedded into `MEMO_HASH` on the [main chain](#main-chain).
* `signature` is the custodian’s signature corresponding to the `issuance_predicate`.





## Peg out specification


#### Preparation step

1. [User](#user) creates a new temporary account `T` that will be used as a uniqueness anchor when performing [withdrawal](#withdrawal). The account must be funded with 2 XLM to satisify minimum account balance and cost of `SetOptions` operation. The remaining balance will be returned to the user’s account.
2. When the temporary account `T` is created, its sequence number is known and can be used in the following step.
3. User forms a withdrawal transaction with the account `T` being the source account with incremented sequence number. Another operation is withdrawal of required quantity of the [original asset](#original-asset) from the custodian’s account. That operation does not consume the sequence number of the custodian, allowing publication of the withdrawal transactions in any order.
4. User computes the withdrawal transaction ID.
5. User signs the withdrawal transaction ID with the T’s key.

#### Export step

User builds an [export transaction](#export) that retires the [mapped asset](#mapped-asset) value with _unblinded commitments_.

User also provides an annotation that links that transaction to an exact state of the temporary account on the [main chain](#main-chain).
The annotation must be done as an immediate `log` instruction that follows the `retire` instruction.
The corresponding entries in the transaction log will be checked to be adjacent to avoid ambiguity and prevent double-withdrawal attacks.

```
<mappedvalue> retire
<memo> log
```

The annotation `memo` is computed as follows:

```
T = Transcript::new("ZkVM.export")
T.commit("anchor_acc", temp_account_id)
T.commit("anchor_seq", temp_account_new_sequence_number)
T.commit("qty", L64E(qty))
T.commit("asset", XDR(Asset))
memo = T.challenge_bytes("memo")
```

The annotation is linked to a unique anchor (account ID + sequence number), and also describes the quantity and the type of the [original asset](#original-asset).

The export transaction is published on the [side chain](#side-chain).

#### Signing step

User sends to custodian:

1. the proof of publication of the export transaction to the [custodian](#custodian),
2. data embedded into the `memo` hash (account id, sequence number, asset structure and quantity),
3. an index of the [retire entry](zkvm-spec.md#retire-entry) in the transaction log,
4. withdrawal transaction formed previously.

Custodian:

1. Checks that the export transaction is actually published (by following merkle path to a block signed via externalized SCP message with pre-arranged quorum slice configuration).
2. Computes the memo hash with the raw data: account ID and sequence number, plaintext quantity and Asset structure.
3. Verifies that this memo hash is embedded in the [log entry](zkvm-spec.md#data-entry) immediately after the [retire entry](zkvm-spec.md#retire-entry) in question.
4. Verifies that the retired quantity is an unblinded commitment to the specified quantity: `Q == qty·B`.
5. Verifies that the retired flavor is an unblinded commitment to the [mapped flavor](#flavor-id-mapping): `F == flv·B`.
6. Verifies that the source of the withdrawal transaction is the specified temporary account.
7. Verifies that the sequence number of the withdrawal transaction is equal to the earlier specified sequence number.
8. Verifies that the first operation is an [Account Merge](https://www.stellar.org/developers/guides/concepts/list-of-operations.html#account-merge).
9. Verifies that the second operation is a payment of exactly `qty` units of the Stellar asset specified above.
10. Verifies that there are no other operations in the transaction.
11. Signs the withdrawal transaction and returns the signature to the user.

Note: this protocol can be safely replayed arbitrary number of times because both the ZkVM retirement and Stellar withdrawal
are tied to the same unique anchor (pair of account ID and sequence number).


#### Withdrawal step

User adds the custodian’s signature to the transaction, alongside with theirs
(to authorize merge of the temporary account), and publishes it on the [main chain](#main-chain).


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

The XDR-encoded metadata is used to compute the issued flavor per [`issue`](zkvm-spec.md#issue) specification
using the custodian’s issuance predicate:

```
T = Transcript("ZkVM.issue")
T.commit("predicate", issuance_predicate)
T.commit("metadata", XDR(Asset))
flavor = T.challenge_scalar("flavor")
```

The resulting _flavor scalar_ is therefore formed as any other flavor, as a combination of the ZkVM issuer (custodian) key and the metadata identifying the Stellar asset.

