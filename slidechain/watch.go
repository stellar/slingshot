package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/davecgh/go-spew/spew"
	i10rnet "github.com/interstellar/starlight/net"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
)

// Runs as a goroutine until ctx is canceled.
func (c *custodian) watchPegs(ctx context.Context) {
	backoff := i10rnet.Backoff{Base: 100 * time.Millisecond}

	var cur horizon.Cursor
	err := c.db.QueryRow("SELECT cursor FROM custodian").Scan(&cur)
	if err != nil && err != sql.ErrNoRows {
		log.Fatal(err)
	}

	for {
		err := c.hclient.StreamTransactions(ctx, c.accountID.Address(), &cur, func(tx horizon.Transaction) {
			log.Printf("handling tx %s", tx.ID)

			var env xdr.TransactionEnvelope
			err := xdr.SafeUnmarshalBase64(tx.EnvelopeXdr, &env)
			if err != nil {
				log.Fatal("error unmarshaling tx: ", err)
			}

			if env.Tx.Memo.Type != xdr.MemoTypeMemoHash {
				return
			}
			recipientPubkey := (*env.Tx.Memo.Hash)[:]

			for i, op := range env.Tx.Operations {
				if op.Body.Type != xdr.OperationTypePayment {
					continue
				}
				payment := op.Body.PaymentOp
				if !payment.Destination.Equals(c.accountID) {
					continue
				}

				// This operation is a payment to the custodian's account - i.e., a peg.
				// We record it in the db, then wake up a goroutine that executes imports for not-yet-imported pegs.
				const q = `INSERT INTO pegs 
					(txid, operation_num, amount, asset_xdr, recipient_pubkey)
					VALUES ($1, $2, $3, $4, $5)`
				assetXDR, err := payment.Asset.MarshalBinary()
				if err != nil {
					log.Fatalf("error marshaling asset to XDR %s: %s", payment.Asset.String(), err)
					return
				}
				_, err = c.db.ExecContext(ctx, q, tx.ID, i, payment.Amount, assetXDR, recipientPubkey)
				if err != nil {
					log.Fatal("error recording peg-in tx: ", err)
					return
				}
				// Update cursor after successfully processing transaction
				_, err = c.db.ExecContext(ctx, `UPDATE custodian SET cursor=$1 WHERE seed=$2`, tx.PT, c.seed)
				if err != nil {
					log.Fatalf("updating cursor: %s", err)
					return
				}
				log.Printf("recorded peg-in tx %s", tx.ID)
				c.imports.Broadcast()
			}
		})
		if err == context.Canceled {
			return
		}
		if err != nil {
			log.Fatal("error streaming from horizon: ", err)
		}
		if err = ctx.Err(); err != nil {
			return
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
func (c *custodian) watchExports(ctx context.Context) {
	r := c.w.Reader()
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

				log.Printf("found retirement: %d of %x", retiredAmount, retiredAssetIDBytes)

				infoItem := tx.Log[i+1]
				if infoItem[0].(txvm.Bytes)[0] != txvm.LogCode {
					log.Print("...never mind, retirement not followed by info log item")
					continue
				}
				var info struct {
					AssetXDR []byte `json:"asset"`
					Account  string `json:"account"`
				}
				err := json.Unmarshal(infoItem[2].(txvm.Bytes), &info)
				if err != nil {
					log.Printf("...never mind, unmarshaling info item produces %s", err)
					continue
				}

				log.Printf("unmarshaling JSON produced this info:\n%s", spew.Sdump(info))

				// Check this Stellar asset code corresponds to retiredAssetIDBytes.
				gotAssetID32 := txvm.AssetID(issueSeed[:], info.AssetXDR)
				if !bytes.Equal(gotAssetID32[:], retiredAssetIDBytes) {
					log.Printf("...never mind, info asset XDR is %x which gives asset ID %x", info.AssetXDR, gotAssetID32[:])
					continue
				}

				var stellarRecipient xdr.AccountId
				err = stellarRecipient.SetAddress(info.Account)
				if err != nil {
					log.Printf("...never mind, setting address of recipient to %s produces %s", info.Account, err)
					continue
				}

				// Record the export in the db,
				// then wake up a goroutine that executes peg-outs on the main chain.
				const q = `
					INSERT INTO exports 
					(txid, recipient, amount, asset_xdr)
					VALUES ($1, $2, $3, $4)`
				_, err = c.db.ExecContext(ctx, q, tx.ID.Bytes(), stellarRecipient.Address(), retiredAmount, info.AssetXDR)
				if err != nil {
					log.Fatalf("recording export tx: %s", err)
				}

				log.Printf("recorded export: %d of txvm asset %x (Stellar %x) for %s", retiredAmount, retiredAssetIDBytes, info.AssetXDR, info.Account)

				c.exports.Broadcast()

				i++ // advance past the consumed log ("L") entry
			}
		}
	}
}
