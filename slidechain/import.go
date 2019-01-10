package main

import (
	"context"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/errors"
)

func (c *custodian) importFromPegs(ctx context.Context, s *submitter) error {
	c.imports.L.Lock()
	defer c.imports.L.Unlock()
	for {
		c.imports.Wait()
		var (
			txids                  []string
			operationNums, amounts []int
			assets                 [][]byte
		)
		const q = `SELECT txid, txhash, operation_num, amount, asset FROM pegs WHERE imported=0`
		err := sqlutil.ForQueryRows(ctx, c.db, q, func(txid string, txhash []byte, operationNum, amount int, asset []byte) {
			txids = append(txids, txid)
			operationNums = append(operationNums, operationNum)
			amounts = append(amounts, amount)
			assets = append(assets, asset)
		})
		// TODO: import the specified row through issuance contract
		for _, txid := range txids {
			_, err = c.db.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE txid=$1`, txid)
			if err != nil {
				return errors.Wrapf(err, "updating record for tx %s", txid)
			}
		}
	}
}
