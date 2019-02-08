package slidechain

import (
	"context"
	"database/sql"
	"log"
	"time"

	i10rnet "github.com/interstellar/starlight/net"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
)

// Runs as a goroutine
func (c *Custodian) retireFromPegOut(ctx context.Context) {
	defer log.Print("retireFromPegOut exiting")
	backoff := i10rnet.Backoff{Base: 100 * time.Millisecond}

	var cur horizon.Cursor
	err := c.DB.QueryRow("SELECT cursor FROM custodian").Scan(&cur)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	for {
		err := c.hclient.StreamTransactions(ctx, c.AccountID.Address(), &cur, func(tx horizon.Transaction) {
			log.Printf("handling Stellar tx %s", tx.ID)

			var env xdr.TransactionEnvelope
			err := xdr.SafeUnmarshalBase64(tx.EnvelopeXdr, &env)
			if err != nil {
				log.Fatal("error unmarshaling Stellar tx: ", err)
			}

			// PRTODO: Include some information for reconstructing the input snapshot in the tx.

			// PRTODO: Loop over the tx.
			for range env.Tx.Operations {
				// PRTODO: Check that this is a payment.

				// PRTODO: Check that this is a payment from custodian to exporter.

				// PRTODO: Execute query to get the appropriate export's row.

				// PRTODO: Update custodian cursor.

				// PRTODO: Run smart contract using the query.

				// PRTODO: Wait for result of the smart contract.

				// PRTODO: Use that result to update information in the exports table.
			}
		})
		if err == context.Canceled {
			return
		}
		if err != nil {
			log.Printf("error streaming from horizon: %s, retrying...", err)
		}
		ch := make(chan struct{})
		go func() {
			time.Sleep(backoff.Next())
			close(ch)
		}()
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}
	}
}
