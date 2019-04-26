# Importing assets from Stellar to ZkVM

This protocol defines the process of importing of assets originally issued on the Stellar into ZkVM and exporting them back to the Stellar network.

The protocol uses _trusted custodian_ secured with multi-signatures and stateless validation (only the blockchain state is used).

## Definitions

Some funds exist on a _main chain_.

These may be _pegged in_.
This means the funds are immobilized and may not be used in any way on the main chain until they are _pegged out_.

Once funds are _pegged in_, they are _imported_ to the sidechain.
Importing means issuing new value on the sidechain that corresponds 1:1 with the pegged-in funds.

Imported funds may subsequently be _exported_. Exported funds are permanently retired from the sidechain.

Once funds have been exported from the sidechain,
the corresponding funds on the main chain may be _pegged out_,
or released from immobilization.

TBD: define user, custodian-node, custodian-signer.

## Peg in

This is a multi-step process that requires actions from
both the user and the custodian who secures the peg.

#### Preparation step

The user prepares an empty output on the ZkVM chain that would uniquely identify the import of assets from the Stellar chain.

The output specifies the stellar asset, quantity and the destination predicate where the user wishes to receive the asset.

TBD: specify the contract

This step requires no cooperation from the custodian.

TBD: this can be extended to support multiple assets imported under one predicate for certain multi-asset contracts.

#### Deposit step

The user makes a Stellar transaction paying the specified quantity of the Stellar asset
with a "memo" field containing the ZkVM output ID.


#### Peg-in step

The custodian-node notices the incoming payment and finds the identified output ID.

Custodian-node forms a transaction that 

TBD: should we automagically make tx on ZkVM, or simply return signed blob to the user to perform tx themselves?
The latter is working better with utxo proofs, and makes less moves on the network, but requires extra actions from the user.
However, user needs to create a token anyway, so these operations can all be turned around quickly within one session (also unconfirmed txs can be chained).


## Peg out

TBD:

## Asset to flavor mapping

To map the stellar asset, we will use `metadata` argument that represents an XDR-encoded `Asset` structure
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
