package main

import (
	"context"
	"database/sql"
)

func importFromPegs(ctx context.Context, db *sql.DB) error {
	for {
		var importedIDs []string
		var q = `SELECT (txid, txhash, operation_num, amount, asset_code) FROM pegs WHERE imported=0`
		rows, err := db.QueryContext(ctx, q)
		defer rows.Close()
		for rows.Next() {
			var (
				txid                 string
				txhash, assetCode    []byte
				operationNum, amount int
			)
			err := rows.Scan(&txid, &txhash, &operationNum, &amount, &assetCode)
			if err != nil {
				return err
			}
			importedIDs = append(importedIDs, txid)
			// TODO: import the specified row through issuance contract
		}
		_, err := db.ExecContext(ctx, `UPDATE pegs SET imported = 1 WHERE txid=unnest($1::text[])`, importedIDs)
		if err != nil {
			return err
		}
	}
}
