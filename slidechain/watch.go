package main

import (
	"context"
	"database/sql"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/interstellar/starlight/worizon"
)

func watchPegs(db *sql.DB) func(worizon.Transaction) error {
	return func(tx worizon.Transaction) error {
		// TODO: Test tx to see if it contains payments to custodian account
		// (or accounts assigned to custodian?).
		// Create entries in "pegs" table as appropriate.
		return nil
	}
}

func watchExports(ctx context.Context, r *multichan.R) {
	for {
		got, ok := r.Read(ctx)
		if !ok {
			return
		}
		b := got.(*bc.Block)
		for _, tx := range b.Transactions {
			// TODO: Test tx to find exports of imported funds.
		}
	}
}
