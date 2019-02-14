package slidechain

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"github.com/bobg/sqlutil"
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

			nonceHash := (*env.Tx.Memo.Hash)[:]
			for _, op := range env.Tx.Operations {
				if op.Body.Type != xdr.OperationTypePayment {
					continue
				}
				payment := op.Body.PaymentOp
				if !payment.Destination.Equals(c.AccountID) {
					continue
				}

				// This operation is a payment to the custodian's account - i.e., a peg.
				// We update the db to note that we saw this entry on the Stellar network.
				// We also populate the amount and asset_xdr with the values in the Stellar tx.
				assetXDR, err := payment.Asset.MarshalBinary()
				if err != nil {
					log.Fatalf("marshaling asset xdr: %s", err)
					return
				}
				resulted, err := c.DB.ExecContext(ctx, `UPDATE pegs SET amount=$1, asset_xdr=$2, stellar_tx=1 WHERE nonce_hash=$3 AND stellar_tx=0`, payment.Amount, assetXDR, nonceHash)
				if err != nil {
					log.Fatalf("updating stellar_tx=1 for hash %x: %s", nonceHash, err)
				}

				// We confirm that only a single row was affected by the update query.
				numAffected, err := resulted.RowsAffected()
				if err != nil {
					log.Fatalf("checking rows affected by update query for hash %x: %s", nonceHash, err)
				}
				if numAffected != 1 {
					log.Fatalf("multiple rows affected by update query for hash %x", nonceHash)
				}

				// We update the cursor to avoid double-processing a transaction.
				_, err = c.DB.ExecContext(ctx, `UPDATE custodian SET cursor=$1 WHERE seed=$2`, tx.PT, c.seed)
				if err != nil {
					log.Fatalf("updating cursor: %s", err)
					return
				}

				// Wake up a goroutine that executes imports for not-yet-imported pegs.
				log.Printf("broadcasting import for tx with nonce hash %x", nonceHash)
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
			// Look for a specially formatted log ("L") entry
			// that specifies the Stellar asset code to peg out and the Stellar recipient account ID.
			// We confirm it is the correct one using the subsequent output ("O") entry.
			for i := 0; i < len(tx.Log)-2; i++ {
				item := tx.Log[i]
				if item[0].(txvm.Bytes)[0] != txvm.LogCode {
					continue
				}

				outputItem := tx.Log[i+1]
				if outputItem[0].(txvm.Bytes)[0] != txvm.OutputCode {
					continue
				}
				// TODO(debnil): Should we do more checks of the output value?

				var info struct {
					AssetXDR []byte `json:"asset"`
					Temp     string `json:"temp"`
					Seqnum   int64  `json:"seqnum"`
					Exporter string `json:"exporter"`
					Amount   int64  `json:"amount"`
				}
				err := json.Unmarshal(item[2].(txvm.Bytes), &info)
				if err != nil {
					continue
				}
				exportedAssetBytes := txvm.AssetID(importIssuanceSeed[:], info.AssetXDR)

				// Record the export in the db,
				// then wake up a goroutine that executes peg-outs on the main chain.
				const q = `
					INSERT INTO exports 
					(txid, exporter, amount, asset_xdr, temp, seqnum)
					VALUES ($1, $2, $3, $4, $5, $6)`
				_, err = c.DB.ExecContext(ctx, q, tx.ID.Bytes(), info.Exporter, info.Amount, info.AssetXDR, info.Temp, info.Seqnum)
				if err != nil {
					log.Fatalf("recording export tx: %s", err)
				}

				log.Printf("recorded export: %d of txvm asset %x (Stellar %x) for %s", info.Amount, exportedAssetBytes, info.AssetXDR, info.Exporter)

				c.exports.Broadcast()

				i++ // advance past the consumed log ("L") entry
			}
		}
	}
}

// Runs as a goroutine
func (c *Custodian) watchPegOuts(ctx context.Context) {
	defer log.Print("watchPegOuts exiting")

	ch := make(chan struct{})
	go func() {
		c.pegouts.L.Lock()
		defer c.pegouts.L.Unlock()
		for {
			if ctx.Err() != nil {
				return
			}
			c.pegouts.Wait()
			ch <- struct{}{}
		}
	}()

	var anchor []byte // TODO(debnil): Insert anchor in db, needed for input snapshot
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}

		var (
			txids, assetXDRs             [][]byte
			amounts, seqnums, peggedOuts []int64
			exporters, temps             []string
		)
		const q = `SELECT txid, amount, asset_xdr, exporter, temp, seqnum, pegged_out FROM exports WHERE exported=1 AND (pegged_out=0 OR pegged_out=1)`
		err := sqlutil.ForQueryRows(ctx, c.DB, q, func(txid []byte, amount int64, assetXDR []byte, exporter, temp string, seqnum, peggedOut int64) {
			txids = append(txids, txid)
			amounts = append(amounts, amount)
			assetXDRs = append(assetXDRs, assetXDR)
			exporters = append(exporters, exporter)
			temps = append(temps, temp)
			seqnums = append(seqnums, seqnum)
			peggedOuts = append(peggedOuts, peggedOut)
		})
		if err == context.Canceled {
			return
		}
		if err != nil {
			log.Fatalf("querying peg-outs: %s", err)
		}
		for i, txid := range txids {
			err = c.doPostExport(ctx, assetXDRs[i], anchor, txid, amounts[i], seqnums[i], peggedOuts[i], exporters[i], temps[i])
			if err != nil {
				if err == context.Canceled {
					return
				}
				log.Fatal(err)
			}
		}
	}
}
