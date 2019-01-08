package main

import (
	"bytes"
	"context"

	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/network"
	"github.com/stellar/go/xdr"
)

// TODO(vniu): pass in real issuance contract seed
var issuanceContractSeed []byte

func (c *custodian) watchPegs(tx horizon.Transaction) {
	var env xdr.TransactionEnvelope
	err := xdr.SafeUnmarshalBase64(tx.EnvelopeXdr, &env)
	if err != nil {
		// TODO(vniu): error handling
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
				(txhash, operation_num, amount, asset_xdr, imported)
				($1, $2, $3, $4, $5, $6)`
		txhash, err := network.HashTransaction(&env.Tx, c.network)
		if err != nil {
			// TODO(vniu): error handling
			return
		}
		assetXDR, err := payment.Asset.MarshalBinary()
		if err != nil {
			// TODO(vniu): error handling
			return
		}
		_, err = c.db.Exec(q, txhash, i, payment.Amount, assetXDR, false)
		if err != nil {
			// TODO(vniu): error handling
			return
		}
		c.imports.Broadcast()
	}
}

func (c *custodian) watchExports(ctx context.Context) {
	r := c.w.Reader()
	for {
		got, ok := r.Read(ctx)
		if !ok {
			return
		}
		b := got.(*bc.Block)
		for _, tx := range b.Transactions {
			// Look for a retire-type ("X") entry followed by two log-type
			// ("L") entries, one specifying the Stellar asset code to peg
			// out and one specifying the Stellar recipient account ID.
			for i := 0; i < len(tx.Log)-3; i++ {
				item := tx.Log[i]
				if len(item) != 5 {
					continue
				}
				if item[0].(txvm.Bytes)[0] != txvm.RetireCode {
					continue
				}
				retiredAmount := int64(item[2].(txvm.Int))
				retiredAssetIDBytes := item[3].(txvm.Bytes)

				stellarAssetCodeItem := tx.Log[i+1]
				if len(stellarAssetCodeItem) != 3 {
					continue
				}
				if stellarAssetCodeItem[0].(txvm.Bytes)[0] != txvm.LogCode {
					continue
				}
				stellarAssetCodeXDR := stellarAssetCodeItem[2].(txvm.Bytes)

				var stellarAsset xdr.Asset
				err := xdr.SafeUnmarshal(stellarAssetCodeXDR, &stellarAsset)
				if err != nil {
					continue
				}

				// Check this Stellar asset code corresponds to retiredAssetIDBytes.
				gotAssetID32 := txvm.AssetID(issuanceContractSeed, stellarAssetCodeXDR)
				if !bytes.Equal(gotAssetID32[:], retiredAssetIDBytes) {
					continue
				}

				stellarRecipientItem := tx.Log[i+2]
				if len(stellarRecipientItem) != 3 {
					continue
				}
				if stellarRecipientItem[0].(txvm.Bytes)[0] != txvm.LogCode {
					continue
				}
				var stellarRecipient xdr.AccountId
				err = xdr.SafeUnmarshal(stellarRecipientItem[2].(txvm.Bytes), &stellarRecipient)
				if err != nil {
					continue
				}

				// Record the export in the db,
				// then wake up a goroutine that executes peg-outs on the main chain.
				const q = `
					INSERT INTO exports 
					(txid, recipient, amount, asset_xdr)
					VALUES ($1, $2, $3, $4)`
				_, err = c.db.ExecContext(ctx, q, tx.ID, stellarRecipient.Address(), retiredAmount, stellarAssetCodeXDR)
				if err != nil {
					// TODO(vniu): error handling
				}
				c.exports.Broadcast()

				i += 2
			}
		}
	}
}
