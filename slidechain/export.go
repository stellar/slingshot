package main

import (
	"context"
	"log"
	"strconv"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/errors"
	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
)

const baseFee = 100

// Runs as a goroutine.
func (c *custodian) pegOutFromExports(ctx context.Context) {
	c.exports.L.Lock()
	defer c.exports.L.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return
		}
		c.exports.Wait()

		const q = `SELECT txid, recipient, amount, asset_xdr FROM exports WHERE exported=0`

		var (
			txids      []string
			recipients []string
			amounts    []int
			assetXDRs  [][]byte
		)
		err := sqlutil.ForQueryRows(ctx, c.db, q, func(txid, recipient string, amount int, assetXDR []byte) {
			txids = append(txids, txid)
			recipients = append(recipients, recipient)
			amounts = append(amounts, amount)
			assetXDRs = append(assetXDRs, assetXDR)
		})
		if err != nil {
			log.Fatal(err, "reading export rows")
		}
		for i, txid := range txids {
			log.Printf("pegging out export %s", txid)
			var recipientID xdr.AccountId
			err := recipientID.SetAddress(recipients[i])
			if err != nil {
				log.Fatal(err, "setting recipient account ID", recipients[i])
			}
			var asset xdr.Asset
			err = xdr.SafeUnmarshal(assetXDRs[i], &asset)
			if err != nil {
				log.Fatal(err, "unmarshalling asset XDR from asset", asset.String())
			}
			// TODO(vniu): flag txs that fail with unretriable errors in the db
			err = c.pegOut(ctx, recipientID, asset, amounts[i])
			if err != nil {
				log.Fatal(err, "pegging out tx")
			}
			_, err = c.db.ExecContext(ctx, `UPDATE exports SET exported=1 WHERE txid=$1`, txid)
			if err != nil {
				log.Fatal(err, "updating export table")
			}
		}
	}
}

func (c *custodian) pegOut(ctx context.Context, recipient xdr.AccountId, asset xdr.Asset, amount int) error {
	tx, err := c.buildPegOutTx(recipient, asset, amount)
	if err != nil {
		return errors.Wrap(err, "building tx")
	}
	txenv, err := tx.Sign(c.seed)
	if err != nil {
		return errors.Wrap(err, "signing tx")
	}
	txstr, err := xdr.MarshalBase64(txenv.E)
	if err != nil {
		return errors.Wrap(err, "marshaling tx to base64")
	}
	resp, err := c.hclient.SubmitTransaction(txstr)
	if err != nil {
		log.Printf("error submitting tx: %s\ntx: %s", err, txstr)
		var (
			resultStr string
			err       error
			tr        xdr.TransactionResult
		)
		if herr, ok := err.(*horizon.Error); ok {
			resultStr, err = herr.ResultString()
			if err != nil {
				log.Print(err, "extracting result string from horizon.Error")
			}
		}
		if resultStr == "" {
			resultStr = resp.Result
			if resultStr == "" {
				log.Print("cannot locate result string from failed tx submission")
			}
		}
		err = xdr.SafeUnmarshalBase64(resultStr, &tr)
		if err != nil {
			log.Print(err, "unmarshaling TransactionResult")
		}
		log.Println("Result: ", resultStr)
	}
	return errors.Wrap(err, "submitting tx")
}

func (c *custodian) buildPegOutTx(recipient xdr.AccountId, asset xdr.Asset, amount int) (*b.TransactionBuilder, error) {
	var paymentOp b.PaymentBuilder
	switch asset.Type {
	case xdr.AssetTypeAssetTypeNative:
		paymentOp = b.Payment(
			b.Destination{AddressOrSeed: recipient.Address()},
			b.NativeAmount{Amount: strconv.Itoa(amount)},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum4:
		paymentOp = b.Payment(
			b.Destination{AddressOrSeed: recipient.Address()},
			b.CreditAmount{
				Code:   string(asset.AlphaNum4.AssetCode[:]),
				Issuer: asset.AlphaNum4.Issuer.Address(),
				Amount: strconv.Itoa(amount),
			},
		)
	case xdr.AssetTypeAssetTypeCreditAlphanum12:
		paymentOp = b.Payment(
			b.Destination{AddressOrSeed: recipient.Address()},
			b.CreditAmount{
				Code:   string(asset.AlphaNum12.AssetCode[:]),
				Issuer: asset.AlphaNum12.Issuer.Address(),
				Amount: strconv.Itoa(amount),
			},
		)
	}
	return b.Transaction(
		b.Network{Passphrase: c.network},
		b.SourceAccount{AddressOrSeed: c.accountID.Address()},
		b.AutoSequence{SequenceProvider: c.hclient},
		b.BaseFee{Amount: baseFee},
		paymentOp,
	)
}
