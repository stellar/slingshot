package main

import (
	"context"
	"database/sql"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/interstellar/starlight/worizon"
	"github.com/stellar/go/xdr"
)

func watchPegs(db *sql.DB) func(worizon.Transaction) error {
	return func(tx worizon.Transaction) error {
		var env xdr.TransactionEnvelope
		err := xdr.SafeUnmarshalBase64(tx.EnvelopeXdr, &env)
		if err != nil {
			return errors.Wrap(err, "unmarshaling envelope XDR")
		}

		for _, op := range env.Tx.Operations {
			if op.Body.Type != xdr.OperationTypePayment {
				continue
			}
			payment := op.Body.PaymentOp
			if !payment.Destination.Equals(custAccountID) {
				continue
			}
			// TODO: this operation is a payment to the custodian's account - i.e., a peg.
			// Record it in the db and/or immediately issue imported funds on the sidechain.
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
			// TODO: Test tx to find exports of imported funds.
		}
	}
}
