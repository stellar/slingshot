package main

import (
	"bytes"
	"context"
	"database/sql"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/network"
	"github.com/stellar/go/xdr"
)

func watchPegs(db *sql.DB, networkPassphrase string) func(horizon.Transaction) error {
	return func(tx horizon.Transaction) error {
		var env xdr.TransactionEnvelope
		err := xdr.SafeUnmarshalBase64(tx.EnvelopeXdr, &env)
		if err != nil {
			return errors.Wrap(err, "unmarshaling envelope XDR")
		}

		for i, op := range env.Tx.Operations {
			if op.Body.Type != xdr.OperationTypePayment {
				continue
			}
			payment := op.Body.PaymentOp
			if !payment.Destination.Equals(custAccountID) {
				continue
			}

			// This operation is a payemtn to the custodian's account - i.e., a peg.
			// We record it in the db and immediately issue imported funds on the sidechain.
			var q = `INSERT INTO pegs 
				(txhash, operation_num, amount, asset_code, imported)
				($1, $2, $3, $4, $5, $6)`
			db.Exec(q, network.TransactionHash(env.Tx, networkPassphrase), i, payment.Amount, payment.Asset.String(), false)
		}
		return nil
	}
}

func watchExports(ctx context.Context, r *multichan.R) {
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

				// TODO: This is an export operation.
				// Record it in the db and/or immediately peg-out funds on the main chain.

				i += 2
			}
		}
	}
}
