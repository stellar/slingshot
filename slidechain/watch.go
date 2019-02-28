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
func (c *Custodian) watchPegIns(ctx context.Context) {
	defer log.Println("watchPegIns exiting")
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
			// Check if the transaction has either expected length for an export tx.
			// Confirm that its input, log, and output entries are as expected.
			// If so, look for a specially formatted log ("L") entry
			// that specifies the Stellar asset code to peg out and the Stellar recipient account ID.
			if len(tx.Log) != 4 && len(tx.Log) != 6 {
				continue
			}
			if tx.Log[0][0].(txvm.Bytes)[0] != txvm.InputCode {
				continue
			}
			if tx.Log[1][0].(txvm.Bytes)[0] != txvm.LogCode {
				continue
			}

			outputIndex := len(tx.Log) - 2
			if tx.Log[outputIndex][0].(txvm.Bytes)[0] != txvm.OutputCode {
				continue
			}

			logItem := tx.Log[1]
			var info pegOut
			err := json.Unmarshal(logItem[2].(txvm.Bytes), &info)
			if err != nil {
				continue
			}
			exportedAssetBytes := txvm.AssetID(importIssuanceSeed[:], info.AssetXDR)

			// Record the export in the db,
			// then wake up a goroutine that executes peg-outs on the main chain.
			const q = `
				INSERT INTO exports 
				(txid, exporter, amount, asset_xdr, temp_addr, seqnum, anchor, pubkey)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
			_, err = c.DB.ExecContext(ctx, q, tx.ID.Bytes(), info.Exporter, info.Amount, info.AssetXDR, info.TempAddr, info.Seqnum, info.Anchor, info.Pubkey)
			if err != nil {
				log.Fatalf("recording export tx: %s", err)
			}

			log.Printf("recorded export: %d of txvm asset %x (Stellar %x) for %s", info.Amount, exportedAssetBytes, info.AssetXDR, info.Exporter)

			c.exports.Broadcast()
		}
	}
}

// Runs as a goroutine.
func (c *Custodian) watchPegOuts(ctx context.Context, pegouts <-chan pegOut) {
	defer log.Print("watchPegOuts exiting")

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			const q = `SELECT amount, asset_xdr, exporter, temp_addr, seqnum, anchor, pubkey FROM exports WHERE pegged_out IN ($1, $2)`
			var (
				txids, anchors, assetXDRs, pubkeys [][]byte
				amounts, seqnums                   []int64
				exporters, tempAddrs               []string
				peggedOuts                         []pegOutState
			)
			err := sqlutil.ForQueryRows(ctx, c.DB, q, pegOutOK, pegOutFail, func(txid []byte, amount int64, assetXDR []byte, exporter, tempAddr string, seqnum, peggedOut int64, anchor, pubkey []byte) {
				txids = append(txids, txid)
				amounts = append(amounts, amount)
				assetXDRs = append(assetXDRs, assetXDR)
				exporters = append(exporters, exporter)
				tempAddrs = append(tempAddrs, tempAddr)
				seqnums = append(seqnums, seqnum)
				peggedOuts = append(peggedOuts, pegOutState(peggedOut))
				anchors = append(anchors, anchor)
				pubkeys = append(pubkeys, pubkey)
			})
			if err != nil {
				log.Fatalf("querying peg-outs: %s", err)
			}
			for i, txid := range txids {
				err = c.doPostPegOut(ctx, assetXDRs[i], anchors[i], txid, amounts[i], seqnums[i], peggedOuts[i], exporters[i], tempAddrs[i], pubkeys[i])
				if err != nil {
					log.Fatalf("doing post-peg-out: %s", err)
				}
			}
		case p, ok := <-pegouts:
			if !ok {
				log.Fatalf("peg-outs channel closed")
			}
			err := c.doPostPegOut(ctx, p.AssetXDR, p.Anchor, p.TxID, p.Amount, p.Seqnum, p.State, p.Exporter, p.TempAddr, p.Pubkey)
			if err != nil {
				log.Fatalf("doing post-peg-out: %s", err)
			}
		}
	}
}
