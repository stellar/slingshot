package slidechain

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	i10rnet "github.com/interstellar/starlight/net"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
)

// Runs as a goroutine until ctx is canceled.
func (c *Custodian) watchPegs(ctx context.Context) {
	defer log.Println("watchPegs exiting")
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

			if env.Tx.Memo.Type != xdr.MemoTypeMemoHash {
				return
			}

			for _, op := range env.Tx.Operations {
				if op.Body.Type != xdr.OperationTypePayment {
					continue
				}
				payment := op.Body.PaymentOp
				if !payment.Destination.Equals(c.AccountID) {
					continue
				}

				// This operation is a payment to the custodian's account - i.e., a peg.
				// We update the cursor to avoid double-processing a transaction.
				_, err = c.DB.ExecContext(ctx, `UPDATE custodian SET cursor=$1 WHERE seed=$2`, tx.PT, c.seed)
				if err != nil {
					log.Fatalf("updating cursor: %s", err)
					return
				}
				// Wake up a goroutine that executes imports for not-yet-imported pegs.
				c.imports.Broadcast()
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

// Runs as a goroutine.
func (c *Custodian) watchExports(ctx context.Context) {
	defer log.Println("watchExports exiting")
	r := c.S.w.Reader()
	for {
		got, ok := r.Read(ctx)
		if !ok {
			if ctx.Err() == context.Canceled {
				return
			}
			log.Fatal("error reading block from multichan")
		}
		b := got.(*bc.Block)
		for _, tx := range b.Transactions {
			// Look for a retire-type ("X") entry
			// followed by a specially formatted log ("L") entry
			// that specifies the Stellar asset code to peg out and the Stellar recipient account ID.

			for i := 0; i < len(tx.Log)-2; i++ {
				item := tx.Log[i]
				if item[0].(txvm.Bytes)[0] != txvm.RetireCode {
					continue
				}
				retiredAmount := int64(item[2].(txvm.Int))
				retiredAssetIDBytes := []byte(item[3].(txvm.Bytes))

				infoItem := tx.Log[i+1]
				if infoItem[0].(txvm.Bytes)[0] != txvm.LogCode {
					continue
				}
				var info struct {
					AssetXDR []byte `json:"asset"`
					Temp     string `json:"temp"`
					Seqnum   int64  `json:"seqnum"`
					Exporter string `json:"exporter"`
				}
				err := json.Unmarshal(infoItem[2].(txvm.Bytes), &info)
				if err != nil {
					continue
				}

				// Check this Stellar asset code corresponds to retiredAssetIDBytes.
				gotAssetID32 := txvm.AssetID(issueSeed[:], info.AssetXDR)
				if !bytes.Equal(gotAssetID32[:], retiredAssetIDBytes) {
					continue
				}

				var exporter xdr.AccountId
				err = exporter.SetAddress(info.Exporter)
				if err != nil {
					continue
				}

				// Record the export in the db,
				// then wake up a goroutine that executes peg-outs on the main chain.
				const q = `
					INSERT INTO exports 
					(txid, exporter, amount, asset_xdr, temp, seqnum)
					VALUES ($1, $2, $3, $4, $5, $6)`
				_, err = c.DB.ExecContext(ctx, q, tx.ID.Bytes(), exporter.Address(), retiredAmount, info.AssetXDR, info.Temp, info.Seqnum)
				if err != nil {
					log.Fatalf("recording export tx: %s", err)
				}

				log.Printf("recorded export: %d of txvm asset %x (Stellar %x) for %s", retiredAmount, retiredAssetIDBytes, info.AssetXDR, exporter.Address())

				c.exports.Broadcast()

				i++ // advance past the consumed log ("L") entry
			}
		}
	}
}
