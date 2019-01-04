package main

import (
	"context"
	"database/sql"

	"github.com/bobg/sqlutil"
)

func importFromPegs(ctx context.Context, db *sql.DB) error {
	for {
		const q = `SELECT txid, txhash, operation_num, amount, asset_code FROM pegs WHERE imported=0`
		err := sqlutil.ForQueryRows(ctx, db, q, func(txid string, txhash []byte, operationNum, amount int, assetCode []byte) error {
			// TODO: import the specified row through issuance contract
			_, err := db.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE txid=$1`, txid)
			if err != nil {
				return err
			}
			return nil
		})
		return err
	}
	return nil
}
