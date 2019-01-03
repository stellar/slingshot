package main

import (
	"context"
	"database/sql"

	"github.com/chain/chain/database/pg"
)

func importFromPegs(ctx context.Context, db *sql.DB) error {
	for {
		var importedIDs []string

		const q = `SELECT txid, txhash, operation_num, amount, asset_code FROM pegs WHERE imported=0`
		err := pg.ForQueryRows(ctx, db, q, func(txid string, txhash []byte, operationNum, amount int, assetCode []byte) error {
			// TODO: import the specified row through issuance contract
			_, err := db.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE txid=$1`, txid)
			if err != nil {
				return err
			}
		})
		return err
	}
	return nil
}
