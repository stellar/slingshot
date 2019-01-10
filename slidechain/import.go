package main

import (
	"context"

	"github.com/chain/txvm/errors"
)

func (c *custodian) importFromPegs(ctx context.Context, s *submitter) error {
	c.imports.L.Lock()
	defer c.imports.L.Unlock()
	for {
		c.imports.Wait()
		const q = `SELECT txid, operation_num, amount, asset_xdr FROM pegs WHERE imported=0`
		rows, err := c.db.Query(q)
		if err != nil {
			return errors.Wrap(err, "querying for pegs to import")
		}
		var (
			txids                  []string
			operationNums, amounts []int
			assets                 [][]byte
		)
		for rows.Next() {
			var (
				txid          string
				opNum, amount int
				asset         []byte
			)
			rows.Scan(&txid, &opNum, &amount, &asset)
			txids = append(txids, txid)
			operationNums = append(operationNums, opNum)
			amounts = append(amounts, amount)
			assets = append(assets, asset)
		}
		for _, txid := range txids {
			_, err = c.db.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE txid=$1`, txid)
			if err != nil {
				return errors.Wrapf(err, "updating record for tx %s", txid)
			}
		}
	}
}
