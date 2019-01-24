package stellar

import (
	"errors"

	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
)

// BuildPegInTx builds a slidechain peg-in transaction
func BuildPegInTx(source string, amount, code, issuer, destination string, hclient *horizon.Client) (*b.TransactionBuilder, error) {
	root, err := hclient.Root()
	if err != nil {
		return nil, err
	}
	var paymentOp b.PaymentBuilder
	if code == "" && issuer == "" {
		paymentOp = b.Payment(
			b.Destination{AddressOrSeed: destination},
			b.NativeAmount{Amount: amount},
		)
	} else {
		paymentOp = b.Payment(
			b.Destination{AddressOrSeed: destination},
			b.CreditAmount{
				Code:   code,
				Issuer: issuer,
				Amount: amount,
			},
		)
	}
	return b.Transaction(
		b.Network{Passphrase: root.NetworkPassphrase},
		b.SourceAccount{AddressOrSeed: source},
		b.AutoSequence{SequenceProvider: hclient},
		b.BaseFee{Amount: 100},
		paymentOp,
	)
}

// NewAsset returns an xdr.Asset for the given code and issuer.
func NewAsset(code, issuer string) (xdr.Asset, error) {
	var issuerAccountID xdr.AccountId
	err := issuerAccountID.SetAddress(issuer)
	if err != nil {
		return xdr.Asset{}, err
	}
	if len(code) > 12 {
		return xdr.Asset{}, errors.New("invalid asset code: max 12 characters")
	}
	if len(code) > 4 {
		var assetCode [12]byte
		copy(assetCode[:], []byte(code))
		return xdr.Asset{
			Type: xdr.AssetTypeAssetTypeCreditAlphanum12,
			AlphaNum12: &xdr.AssetAlphaNum12{
				AssetCode: assetCode,
				Issuer:    issuerAccountID,
			},
		}, nil
	}
	var assetCode [4]byte
	copy(assetCode[:], []byte(code))
	return xdr.Asset{
		Type: xdr.AssetTypeAssetTypeCreditAlphanum4,
		AlphaNum4: &xdr.AssetAlphaNum4{
			AssetCode: assetCode,
			Issuer:    issuerAccountID,
		},
	}, nil
}

// NativeAsset returns the xdr.Asset object for lumens.
func NativeAsset() xdr.Asset {
	return xdr.Asset{
		Type: xdr.AssetTypeAssetTypeNative,
	}
}
