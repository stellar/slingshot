package main

import (
	"context"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/errors"
)

// Runs as a goroutine.
func (c *custodian) importFromPegs(ctx context.Context, s *submitter) {
	c.imports.L.Lock()
	defer c.imports.L.Unlock()
	for {
		c.imports.Wait()
		if err := ctx.Err(); err != nil {
			return
		}
		var (
			txids          []string
			opNums         []int
			amounts        []int64
			assets, recips [][]byte
		)
		const q = `SELECT txid, txhash, operation_num, amount, asset, recipient_pubkey FROM pegs WHERE imported=0`
		err := sqlutil.ForQueryRows(ctx, c.db, q, func(txid string, txhash []byte, opNum int, amount int64, asset, recip []byte) {
			txids = append(txids, txid)
			opNums = append(opNums, opNum)
			amounts = append(amounts, amount)
			assets = append(assets, asset)
			recips = append(recips, recip)
		})
		for i, txid := range txids {
			var (
				opNum  = opNums[i]
				amount = amounts[i]
				asset  = assets[i]
				recip  = recips[i]
			)
			err = c.doImport(ctx, s, txid, opNum, amount, asset, recip) // TODO(bobg): probably s should be a field in the custodian object
			if err != nil {
				if err == context.Canceled {
					return
				}
				log.Fatal(err)
			}
		})
	}
}

func (c *custodian) doImport(ctx context.Context, s *submitter, txid string, opNum int, amount int64, assetXDR, recip []byte) error {
	// TODO: build and submit import transaction
	_, err := c.db.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE txid = $1 AND operation_num = $2`, txid, opNum)
	return errors.Wrapf(err, "setting imported=1 for txid %s, operation %d", txid, opNum)
}
