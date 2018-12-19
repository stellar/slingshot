package main

import (
	"database/sql"

	"i10r.io/protocol/bc"
	"i10r.io/worizon"
)

func watchPegs(db *sql.DB) func(worizon.Transaction) error {
	return func(tx worizon.Transaction) error {
		// TODO: Test tx to see if it contains payments to custodian account
		// (or accounts assigned to custodian?).
		// Create entries in "pegs" table as appropriate.
		return nil
	}
}

func watchUnpegs(blocks <-chan *bc.Block) {
	for b := range blocks {
		for _, tx := range b.Transactions {
			// TODO: Test tx to find invocations of unpeg contracts.
			// Match those with db records and release the pegged funds on the main chain back to the originating account.
		}
	}
}
