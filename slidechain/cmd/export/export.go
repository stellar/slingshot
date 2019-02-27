package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/interstellar/slingshot/slidechain"
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/interstellar/starlight/worizon/xlm"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
)

func main() {
	var (
		prv         = flag.String("prv", "", "hex encoding of ed25519 key for txvm and Stellar account")
		amount      = flag.String("amount", "", "amount to export")
		anchor      = flag.String("anchor", "", "txvm anchor of input to consume")
		input       = flag.String("input", "", "total amount of input")
		slidechaind = flag.String("slidechaind", "http://127.0.0.1:2423", "url of slidechaind server")
		code        = flag.String("code", "", "asset code if exporting non-lumen Stellar asset")
		issuer      = flag.String("issuer", "", "issuer of asset if exporting non-lumen Stellar asset")
	)

	flag.Parse()
	if *amount == "" {
		log.Fatal("must specify amount to peg-out")
	}
	if *anchor == "" {
		log.Fatal("must specify txvm input anchor")
	}
	if *prv == "" {
		log.Fatal("must specify txvm account keypair")
	}
	if (*code != "" && *issuer == "") || (*code == "" && *issuer != "") {
		log.Fatal("must specify both code and issuer for non-lumen Stellar asset")
	}
	if *input == "" {
		log.Printf("no input amount specified, default to export amount %s", *amount)
		*input = *amount
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	var err error
	asset := stellar.NativeAsset()
	if *code != "" {
		asset, err = stellar.NewAsset(*code, *issuer)
		if err != nil {
			log.Fatalf("error creating asset from code %s and issuer %s: %s", *code, *issuer, err)
		}
	}

	// XDR scales down an amount unit of every asset by a factor of 10^7.
	// Thus, xlm.Parse works for both native and non-native assets.
	exportAmount, err := xlm.Parse(*amount)
	if err != nil {
		log.Fatalf("error parsing export amount %s: %s", *amount, err)
	}
	inputAmount, err := xlm.Parse(*input)
	if err != nil {
		log.Fatalf("error parsing input amount %s: %s", *input, err)
	}

	*slidechaind = strings.TrimRight(*slidechaind, "/")

	// Build and submit the pre-export transaction.

	// Check that stellar account exists.
	var seed [32]byte
	rawbytes := mustDecodeHex(*prv)
	copy(seed[:], rawbytes)
	kp, err := keypair.FromRawSeed(seed)
	hclient := horizon.DefaultTestNetClient
	if _, err := hclient.SequenceForAccount(kp.Address()); err != nil {
		err := stellar.FundAccount(kp.Address())
		if err != nil {
			log.Fatalf("error funding Stellar account %s: %s", kp.Address(), err)
		}
	}
	var custodian xdr.AccountId
	resp, err := http.Get(*slidechaind + "/account")
	if err != nil {
		log.Fatalf("error getting custodian address: %s", err)
	}
	defer resp.Body.Close()
	_, err = xdr.Unmarshal(resp.Body, &custodian)
	if err != nil {
		log.Fatalf("error unmarshaling custodian account id: %s", err)
	}
	tempAddr, seqnum, err := slidechain.SubmitPreExportTx(hclient, kp, custodian.Address(), asset, int64(exportAmount))
	if err != nil {
		log.Fatalf("error submitting pre-export tx: %s", err)
	}

	// Export funds from slidechain.
	tx, err := slidechain.BuildExportTx(ctx, asset, int64(exportAmount), int64(inputAmount), tempAddr, mustDecodeHex(*anchor), rawbytes, seqnum)
	if err != nil {
		log.Fatalf("error building export tx: %s", err)
	}
	txbits, err := proto.Marshal(&tx.RawTx)
	if err != nil {
		log.Fatal(err)
	}

	// Submit the transaction and block until it's included in the txvm chain (or returns an error).
	req, err := http.NewRequest("POST", *slidechaind+"/submit?wait=1", bytes.NewReader(txbits))
	if err != nil {
		log.Fatalf("error building request for latest block: %s", err)
	}
	req = req.WithContext(ctx)
	client := http.DefaultClient
	resp, err = client.Do(req)
	if err != nil {
		log.Fatalf("error submitting and waiting on tx to slidechaind: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Fatalf("bad status code %d from POST /submit?wait=1", resp.StatusCode)
	}
	log.Printf("successfully submitted export transaction: %x", tx.ID)
}

func mustDecodeHex(src string) []byte {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		panic(fmt.Errorf("error decoding %s: %s", src, err))
	}
	return bytes
}
