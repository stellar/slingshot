package main

import (
	"context"
	"database/sql"
	"strings"

	"github.com/bobg/sqlutil"
	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
)

const baseFee = 10

func pegOutFromExports(ctx context.Context, db *sql.DB, hclient *horizon.Client, custAccountID xdr.AccountId) error {
	for {
		const q = `SELECT txid, recipient, amount, asset_code FROM exports WHERE exported=0`
		err := sqlutil.ForQueryRows(ctx, db, q, func(txid, recipient string, amount int, assetCode string) error {
			var recipientID xdr.AccountId
			err := recipientID.SetAddress(recipient)
			if err != nil {
				return err
			}
			s := strings.Split(assetCode, "/")
			code, issuer := s[1], s[2]
			err = pegOut(ctx, hclient, custAccountID, recipientID, code, issuer, amount)
			if err != nil {
				return err
			}
			_, err = db.ExecContext(ctx, `UPDATE exports SET exported=1 WHERE txid=$1`, txid)
			return err
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func pegOut(ctx context.Context, hclient *horizon.Client, custAccountID, recipient xdr.AccountId, code, issuer string, amount int) error {
	// TOOD(vniu): get seed
	var seed string
	root, err := hclient.Root()
	if err != nil {
		return err
	}
	tx, err := buildPegOutTx(root.NetworkPassphrase, custAccountID, recipient, code, issuer, amount)
	// TODO(vniu): retry tx submission
	txenv, err := tx.Sign(seed)
	if err != nil {
		return err
	}
	txstr, err := xdr.MarshalBase64(txenv.E)
	if err != nil {
		return err
	}
	succ, err := hclient.SubmitTransaction(txstr)
	return err
}

func buildPegOutTx(passphrase string, custAccountID, recipient xdr.AccountId, code, issuer string, amount int) (*b.TransactionBuilder, error) {
	// TODO(vniu): track account seqnum
	var seqnum xdr.SequenceNumber
	return b.Transaction(
		b.Network{Passphrase: passphrase},
		b.SourceAccount{AddressOrSeed: custAccountID.Address()},
		b.Sequence{Sequence: uint64(seqnum)},
		b.BaseFee{Amount: baseFee},
		b.Payment(
			b.Destination{AddressOrSeed: recipient.Address()},
			b.CreditAmount{
				Code:   code,
				Issuer: issuer,
				// TODO(vniu): better amount-to-string conversion
				Amount: string(amount),
			},
		),
	)
}
