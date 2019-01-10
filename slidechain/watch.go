package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
)

func (c *custodian) watchPegs(tx horizon.Transaction) {
	var env xdr.TransactionEnvelope
	err := xdr.SafeUnmarshalBase64(tx.EnvelopeXdr, &env)
	if err != nil {
		log.Fatal("error unmarshaling tx: ", err)
		return
	}

	for i, op := range env.Tx.Operations {
		if op.Body.Type != xdr.OperationTypePayment {
			continue
		}
		payment := op.Body.PaymentOp
		if !payment.Destination.Equals(c.accountID) {
			continue
		}

		// This operation is a payment to the custodian's account - i.e., a peg.
		// We record it in the db, then wake up a goroutine that executes imports for not-yet-imported pegs.
		var q = `INSERT INTO pegs 
				(txid, operation_num, amount, asset_xdr, imported)
				VALUES ($1, $2, $3, $4, $5)`
		assetXDR, err := payment.Asset.MarshalBinary()
		if err != nil {
			log.Fatalf("error marshaling asset to XDR %s: %s", payment.Asset.String(), err)
			return
		}
		_, err = c.db.Exec(q, tx.ID, i, payment.Amount, assetXDR, false)
		if err != nil {
			log.Fatal("error recording peg-in tx: ", err)
			return
		}
		c.imports.Broadcast()
	}
	return
}

func (c *custodian) watchExports(ctx context.Context) error {
	r := c.w.Reader()
	for {
		got, ok := r.Read(ctx)
		if !ok {
			return errors.New("error reading block from multichan")
		}
		b := got.(*bc.Block)
		for _, tx := range b.Transactions {
			// Look for a retire-type ("X") entry
			// followed by a specially formatted log ("L") entry
			// that specifies the Stellar asset code to peg out and the Stellar recipient account ID.

			for i := 0; i < len(tx.Log)-2; i++ {
				item := tx.Log[i]
				if len(item) != 5 {
					continue
				}
				if item[0].(txvm.Bytes)[0] != txvm.RetireCode {
					continue
				}
				retiredAmount := int64(item[2].(txvm.Int))
				retiredAssetIDBytes := item[3].(txvm.Bytes)

				infoItem := tx.Log[i+1]
				if infoItem[0].(txvm.Bytes)[0] != txvm.LogCode {
					continue
				}
				var info struct {
					AssetXDR   []byte `json:"asset"`
					AccountXDR []byte `json:"account"`
				}
				err := json.Unmarshal(infoItem[2].(txvm.Bytes), &info)
				if err != nil {
					continue
				}

				// Check this Stellar asset code corresponds to retiredAssetIDBytes.
				gotAssetID32 := txvm.AssetID(issueSeed[:], info.AssetXDR)
				if !bytes.Equal(gotAssetID32[:], retiredAssetIDBytes) {
					continue
				}

				var stellarRecipient xdr.AccountId
				err = xdr.SafeUnmarshal(info.AccountXDR, &stellarRecipient)
				if err != nil {
					continue
				}

				// Record the export in the db,
				// then wake up a goroutine that executes peg-outs on the main chain.
				const q = `
					INSERT INTO exports 
					(txid, recipient, amount, asset_xdr)
					VALUES ($1, $2, $3, $4)`
				_, err = c.db.ExecContext(ctx, q, tx.ID, stellarRecipient.Address(), retiredAmount, info.AssetXDR)
				if err != nil {
					return errors.Wrap(err, "recording export tx")
				}
				c.exports.Broadcast()

				i++ // advance past the consumed log ("L") entry
			}
		}
	}
}
