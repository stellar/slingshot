package slidechain

import (
	"context"
	"fmt"
	"log"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
)

// RunPin runs as a goroutine.
func (c *Custodian) RunPin(ctx context.Context, name string, f func(context.Context, *bc.Block) error) {
	defer log.Printf("RunPin(%s) exiting", name)

	r := c.S.w.Reader()

	_, err := c.DB.ExecContext(ctx, `INSERT OR IGNORE INTO pins (name, height) VALUES ($1, 0)`, name)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		log.Fatalf("creating pin %s: %s", name, err)
	}

	var lastHeight uint64
	err = c.DB.QueryRowContext(ctx, `SELECT height FROM pins WHERE name = $1`, name).Scan(&lastHeight)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		log.Fatalf("getting height of pin %s: %s", name, err)
	}

	// Start processing after lastHeight.

	var blocks []*bc.Block
	err = sqlutil.ForQueryRows(ctx, c.DB, `SELECT bits, height FROM blocks WHERE height > $1 ORDER BY height`, lastHeight, func(bits []byte, height uint64) error {
		var block bc.Block
		err = block.FromBytes(bits)
		if err != nil {
			return errors.Wrapf(err, "unmarshaling block %d", height)
		}
		blocks = append(blocks, &block)
		return nil
	})
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		log.Fatalf("processing backlog for pin %s: %s", name, err)
	}

	processBlock := func(block *bc.Block) error {
		if block.Height != lastHeight+1 {
			return fmt.Errorf("missing block %d", lastHeight+1)
		}
		err = f(ctx, block)
		if err != nil {
			return errors.Wrapf(err, "running pin %s on block %d", name, block.Height)
		}
		_, err = c.DB.Exec(`UPDATE pins SET height = $1 WHERE name = $2`, block.Height, name) // n.b. not ExecContext
		if err != nil {
			return errors.Wrapf(err, "updating pin %s after block %d", name, block.Height)
		}
		lastHeight = block.Height
		return nil
	}

	for _, block := range blocks {
		err = processBlock(block)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Fatalf("processing backlog block %d: %s", block.Height, err)
		}
	}

	for {
		x, ok := r.Read(ctx)
		if !ok {
			if ctx.Err() != nil {
				return
			}
			log.Fatalf("error waiting for block %d", lastHeight+1)
		}
		block := x.(*bc.Block)
		if block.Height <= lastHeight {
			continue
		}
		err = processBlock(block)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Fatalf("processing live block %d: %s", block.Height, err)
		}
	}
}
