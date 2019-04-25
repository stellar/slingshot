# Importing assets from Stellar to ZkVM

This protocol defines the process of importing of assets originally issued on the Stellar into ZkVM and exporting them back to the Stellar network.

The protocol uses _trusted custodian_ secured with multi-signatures and stateless validation (only the blockchain state is used).

## Importing assets

TBD:

## Exporting assets

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
