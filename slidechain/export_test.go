package slidechain

import (
	"context"
	"database/sql"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
)

func TestPegOut(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	testdir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(testdir)
	db, err := sql.Open("sqlite3", fmt.Sprintf("%s/testdb", testdir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	c, err := GetCustodian(ctx, db, "https://horizon-testnet.stellar.org")
	if err != nil {
		t.Fatal(err)
	}

	var lumen xdr.Asset
	lumen.Type = xdr.AssetTypeAssetTypeNative
	lumenXDR, err := lumen.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	kp, err := keypair.Random()
	if err != nil {
		t.Fatal(err)
	}
	destination := kp.Address()
	resp, err := http.Get("https://friendbot.stellar.org/?addr=" + destination)
	if err != nil {
		t.Fatal(err, "requesting lumens through friendbot")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("got bad status code %d funding destination address through friendbot", resp.StatusCode)
	}
	log.Printf("successfully funded destination account %s", destination)

	_, err = c.DB.Exec("INSERT INTO exports (txid, recipient, amount, asset_xdr) VALUES ($1, $2, $3, $4)", "", destination, 50, lumenXDR)
	if err != nil && err != context.Canceled {
		t.Fatal(err)
	}

	c.exports <- struct{}{}

	ch := make(chan struct{})

	go func() {
		var cursor horizon.Cursor
		for {
			err := c.hclient.StreamTransactions(ctx, destination, &cursor, func(tx horizon.Transaction) {
				log.Printf("received tx: %s", tx.EnvelopeXdr)
				var env xdr.TransactionEnvelope
				err := xdr.SafeUnmarshalBase64(tx.EnvelopeXdr, &env)
				if err != nil {
					t.Fatal(err)
				}
				if env.Tx.SourceAccount.Address() != c.accountID.Address() {
					log.Println("source accounts don't match, skipping...")
					return
				}
				if len(env.Tx.Operations) != 1 {
					t.Fatalf("too many operations got %d, want 1", len(env.Tx.Operations))
				}
				op := env.Tx.Operations[0]
				if op.Body.Type != xdr.OperationTypePayment {
					t.Fatalf("wrong operation type: got %s, want %s", op.Body.Type, xdr.OperationTypePayment)
				}
				paymentOp := op.Body.PaymentOp
				if paymentOp.Destination.Address() != destination {
					t.Fatalf("incorrect payment destination got %s, want %s", paymentOp.Destination.Address(), destination)
				}
				if paymentOp.Amount != 50 {
					t.Fatalf("got incorrect payment amount %d, want %d", paymentOp.Amount, 50)
				}
				if paymentOp.Asset.Type != xdr.AssetTypeAssetTypeNative {
					t.Fatalf("got incorrect payment asset %s, want lumens", paymentOp.Asset.String())
				}
				close(ch)
			})
			if err != nil {
				log.Printf("error streaming from Horizon: %s, retrying in 1s", err)
				time.Sleep(time.Second)
			}
		}
	}()

	select {
	case <-ctx.Done():
		t.Fatal("context timed out: no peg-out tx seen")
	case <-ch:
	}
}
