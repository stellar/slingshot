package main

import (
	"context"

	"github.com/bobg/sqlutil"
)

func (c *custodian) importFromPegs(ctx context.Context, s *submitter) error {
	c.imports.L.Lock()
	defer c.imports.L.Unlock()
	for {
		c.imports.Wait()
		const q = `SELECT txid, txhash, operation_num, amount, asset FROM pegs WHERE imported=0`
		err := sqlutil.ForQueryRows(ctx, c.db, q, func(txid string, txhash []byte, operationNum, amount int, asset []byte) error {
			// TODO: import the specified row through issuance contract
			_, err := c.db.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE txid=$1`, txid)
			if err != nil {
				return err
			}
			return nil
		})
		return err
	}
}
