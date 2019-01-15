package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"testing"

	"github.com/stellar/go/clients/horizon"

	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
)

const stroopsToLumens = 10000000

func TestExports(t *testing.T) {
	ctx := context.Background()
	testdir, err := ioutil.TempDir("", t.Name())
	if err != nil {
		t.Fatal(err)
	}
	c, err := start(ctx, fmt.Sprintf("%s/testdb", testdir), "https://horizon-testnet.stellar.org")

	go c.pegOutFromExports(ctx)

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

	_, err = c.db.Exec("INSERT INTO exports (txid, recipient, amount, asset_xdr) VALUES ($1, $2, $3, $4)", "", destination, 50, lumenXDR)
	if err != nil {
		t.Fatal(err)
	}

	c.exports.Broadcast()

	ch := make(chan struct{})

	go func() {
		var cursor horizon.Cursor
		c.hclient.StreamTransactions(ctx, destination, &cursor, func(tx horizon.Transaction) {
			log.Println("read a tx!")
			log.Println(tx.EnvelopeXdr)
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
				log.Println("too many operations, skipping...")
				return
			}
			op := env.Tx.Operations[0]
			if op.Body.Type != xdr.OperationTypePayment {
				log.Println("wrong operation type, skipping...")
				return
			}
			paymentOp := op.Body.PaymentOp
			if paymentOp.Destination.Address() != destination {
				t.Fatalf("incorrect payment destination got %s, want %s", paymentOp.Destination.Address(), destination)
			}
			if paymentOp.Amount != 50*stroopsToLumens {
				t.Fatalf("got incorrect payment amount %d, want %d", paymentOp.Amount, 50)
			}
			if paymentOp.Asset.Type != xdr.AssetTypeAssetTypeNative {
				t.Fatalf("got incorrect payment asset %s, want lumens", paymentOp.Asset.String())
			}
			close(ch)
		})
	}()

	<-ch
}
