package slidechain

import (
	"context"
	"database/sql"
	"fmt"
	"log"

	"github.com/bobg/multichan"
	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/golang/protobuf/proto"
)

// RunPin runs as a goroutine.
func (c *Custodian) RunPin(ctx context.Context, name string, f func(context.Context, *bc.Block) error) {
	defer log.Printf("RunPin(%s) exiting", name)

	r := c.S.w.Reader()

	_, err := c.DB.ExecContext(`INSERT OR IGNORE INTO pin (name, height) VALUES ($1, 0)`, name)
	if err != nil {
		// xxx
	}

	var lastHeight uint64
	err = c.DB.QueryRowContext(ctx, `SELECT height FROM pin WHERE name = $1`, name).Scan(&lastHeight)
	if err != nil {
		// xxx
	}

	// Start processing after lastHeight.

	var blocks []*bc.Block
	err = sqlutil.ForQueryRows(ctx, c.DB, `SELECT bits, height FROM blocks WHERE height > $1 ORDER BY height`, lastHeight, func(bits []byte, height uint64) error {
		var block bc.Block
		err = proto.Unmarshal(bits, &block)
		if err != nil {
			return errors.Wrapf(err, "unmarshaling block %d", height)
		}
		blocks = append(blocks, &block)
		return nil
	})
	if err != nil {
		// xxx
	}

	processBlock := func(block *bc.Block) error {
		if block.Height != lastHeight+1 {
			return fmt.Errorf("missing block %d", lastHeight+1)
		}
		err = f(ctx, block)
		if err != nil {
			return errors.Wrapf(err, "running pin %s on block %d", name, block.Height)
		}
		_, err = c.DB.ExecContext(ctx, `UPDATE pin SET height = $1 WHERE name = $2`, block.Height, name)
		if err != nil {
			return errors.Wrapf(err, "updating pin %s after block %d", name, block.Height)
		}
		lastHeight = block.Height
	}

	for _, block := range blocks {
		err = processBlock(block)
		if err != nil {
			// xxx
		}
	}

	for {
		x, ok := r.Read(ctx)
		if !ok {
			if ctx.Err() != nil {
				return
			}
			// xxx
		}
		block := x.(*bc.Block)
		if block.Height <= lastHeight {
			continue
		}
		err = processBlock(block)
		if err != nil {
			// xxx
		}
	}
}
