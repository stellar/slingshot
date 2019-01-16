package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"

	"slingshot/slidechain"

	"github.com/golang/protobuf/proto"
	"github.com/stellar/go/xdr"
)

func main() {
	var (
		dest   = flag.String("destination", "", "Stellar address to peg funds out to")
		amount = flag.Int("amount", 0, "amount to export")
		anchor = flag.String("anchor", "", "txvm anchor of input to consume")
		prv    = flag.String("prv", "", "private key of txvm account")
		pub    = flag.String("pub", "", "public key of txvm account")
	)

	flag.Parse()
	if *dest == "" {
		log.Fatal("must specify peg-out destination")
	}
	if *amount == 0 {
		log.Fatal("must specify amount to peg-out")
	}
	if *anchor == "" {
		log.Fatal("must specify txvm input anchor")
	}
	if *prv == "" || *pub == "" {
		log.Fatal("must specify txvm account keypair")
	}
	ctx := context.Background()
	native := xdr.Asset{
		Type: xdr.AssetTypeAssetTypeNative,
	}
	tx, err := slidechain.BuildExportTx(ctx, native, int64(*amount), *dest, mustDecode(*anchor), mustDecode(*prv), mustDecode(*pub))
	if err != nil {
		log.Fatalf("error building export tx: %s", err)
	}
	txbits, err := proto.Marshal(&tx.RawTx)
	if err != nil {
		log.Fatal(err)
	}
	log.Print(txbits)
}

func mustDecode(src string) []byte {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		log.Fatalf("error decoding %s: %s", src, err)
	}
	return bytes
}
