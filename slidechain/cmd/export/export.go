package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/protocol/bc"
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
	var (
		asset        xdr.Asset
		exportAmount int64
		inputAmount  int64
		err          error
	)
	if *code != "" {
		asset, err = stellar.NewAsset(*code, *issuer)
		if err != nil {
			log.Fatalf("error creating asset from code %s and issuer %s: %s", *code, *issuer, err)
		}
		exportAmount, err = strconv.ParseInt(*amount, 10, 64)
		if err != nil {
			log.Fatalf("error parsing export amount %s: %s", *amount, err)
		}
		inputAmount, err = strconv.ParseInt(*input, 10, 64)
		if err != nil {
			log.Fatalf("error parsing input amount %s: %s", *input, err)
		}
	} else {
		asset = stellar.NativeAsset()
		exportXlm, err := xlm.Parse(*amount)
		if err != nil {
			log.Fatalf("error parsing export amount %s: %s", *amount, err)
		}
		exportAmount = int64(exportXlm)
		inputXlm, err := xlm.Parse(*input)
		if err != nil {
			log.Fatalf("error parsing input amount %s: %s", *input, err)
		}
		inputAmount = int64(inputXlm)
	}
	*slidechaind = strings.TrimRight(*slidechaind, "/")

	// Build + submit pre-export tx

	// Check that stellar account exists
	var seed [32]byte
	rawbytes := mustDecode(*prv)
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
	temp, seqnum, err := slidechain.SubmitPreExportTx(hclient, kp, custodian.Address(), asset, exportAmount)
	if err != nil {
		log.Fatalf("error submitting pre-export tx: %s", err)
	}

	// Export funds from slidechain
	tx, err := slidechain.BuildExportTx(ctx, asset, exportAmount, inputAmount, temp, mustDecode(*anchor), mustDecode(*prv), seqnum)
	if err != nil {
		log.Fatalf("error building export tx: %s", err)
	}
	txbits, err := proto.Marshal(&tx.RawTx)
	if err != nil {
		log.Fatal(err)
	}

	// Get latest block height
	resp, err = http.Get(*slidechaind + "/get?height=0")
	if err != nil {
		log.Fatalf("error getting latest block height: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Fatalf("bad status code %d getting latest block height", resp.StatusCode)
	}
	block := new(bc.Block)
	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("error reading block from response body: %s", err)
	}
	err = block.FromBytes(bits)
	if err != nil {
		log.Fatalf("error unmarshaling block: %s", err)
	}

	resp, err = http.Post(*slidechaind+"/submit", "application/octet-stream", bytes.NewReader(txbits))
	if err != nil {
		log.Fatalf("error submitting tx to slidechaind: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Fatalf("status code %d from POST /submit", resp.StatusCode)
	}
	log.Printf("successfully submitted export transaction: %x", tx.ID)

	client := http.DefaultClient
	pubkey := ed25519.PrivateKey(mustDecode(*prv)).Public().(ed25519.PublicKey)
	for height := block.Height + 1; ; height++ {
		req, err := http.NewRequest("GET", fmt.Sprintf(*slidechaind+"/get?height=%d", height), nil)
		if err != nil {
			log.Fatalf("error building request for latest block: %s", err)
		}
		req = req.WithContext(ctx)
		resp, err = client.Do(req)
		if err != nil {
			log.Fatalf("error getting block at height %d: %s", height, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			log.Fatalf("bad status code %d getting latest block height", resp.StatusCode)
		}
		b := new(bc.Block)
		bits, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatalf("error reading block from response body: %s", err)
		}
		err = b.FromBytes(bits)
		if err != nil {
			log.Fatalf("error unmarshaling block: %s", err)
		}
		for _, tx := range b.Transactions {
			// Look for export transaction
			if slidechain.IsExportTx(tx, asset, inputAmount, temp, kp.Address(), int64(seqnum), mustDecode(*anchor), pubkey) {
				log.Println("export tx included in txvm chain")
				return
			}
		}
	}
}

func mustDecode(src string) []byte {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		log.Fatalf("error decoding %s: %s", src, err)
	}
	return bytes
}
