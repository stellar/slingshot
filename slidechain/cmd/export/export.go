package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"strings"

	"github.com/golang/protobuf/proto"
	"github.com/interstellar/slingshot/slidechain"
	"github.com/interstellar/starlight/worizon/xlm"
	"github.com/stellar/go/xdr"
)

func main() {
	var (
		dest        = flag.String("destination", "", "Stellar address to peg funds out to")
		amount      = flag.String("amount", "", "amount to export")
		anchor      = flag.String("anchor", "", "txvm anchor of input to consume")
		prv         = flag.String("prv", "", "private key of txvm account")
		slidechaind = flag.String("slidechaind", "http://127.0.0.1:2423", "url of slidechaind server")
	)

	flag.Parse()
	if *dest == "" {
		log.Fatal("must specify peg-out destination")
	}
	if *amount == "" {
		log.Fatal("must specify amount to peg-out")
	}
	if *anchor == "" {
		log.Fatal("must specify txvm input anchor")
	}
	if *prv == "" {
		log.Fatal("must specify txvm account keypair")
	}
	ctx := context.Background()
	native := xdr.Asset{
		Type: xdr.AssetTypeAssetTypeNative,
	}
	xlmAmount, err := xlm.Parse(*amount)
	if err != nil {
		log.Fatalf("error parsing amount %s", *amount)
	}
	// TODO(vniu): add functionality to only export a portion of the given utxo, and pay back the change to the utxo owner.
	tx, err := slidechain.BuildExportTx(ctx, native, int64(xlmAmount), *dest, mustDecode(*anchor), mustDecode(*prv))
	if err != nil {
		log.Fatalf("error building export tx: %s", err)
	}
	txbits, err := proto.Marshal(&tx.RawTx)
	if err != nil {
		log.Fatal(err)
	}
	resp, err := http.Post(strings.TrimRight(*slidechaind, "/")+"/submit", "application/octet-stream", bytes.NewReader(txbits))
	if err != nil {
		log.Fatalf("error submitting tx to slidechaind: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Fatalf("status code %d from POST /submit", resp.StatusCode)
	}
	log.Printf("successfully submitted export transaction: %x", tx.ID)
}

func mustDecode(src string) []byte {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		log.Fatalf("error decoding %s: %s", src, err)
	}
	return bytes
}
