package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
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
	temp, seqnum, err := slidechain.SubmitPreExportTx(ctx, hclient, custodian.Address(), kp)
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
	height := block.Height

	resp, err = http.Post(*slidechaind+"/submit", "application/octet-stream", bytes.NewReader(txbits))
	if err != nil {
		log.Fatalf("error submitting tx to slidechaind: %s", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		log.Fatalf("status code %d from POST /submit", resp.StatusCode)
	}
	log.Printf("successfully submitted export transaction: %x", tx.ID)

	for {
		if ctx.Err() != nil {
			log.Println("command timed out, export tx not found")
			return
		}
		resp, err = http.Get(fmt.Sprintf(*slidechaind+"/get?height=%d", height))
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
			if isExportTx(tx, asset, inputAmount, temp, kp.Address(), int64(seqnum)) {
				log.Println("export tx included in txvm chain")
				return
			}
		}
		height++
	}
}

// Expected log is:
// For an export that fully consumes the input:
// {"I", ...}
// {"L", ...}
// {"X", vm seed, inputAmount, asset id, anchor}
// {"L", vm seed, refdata}
// {"R", ...} timerange
// {"L", ...}
// {"F", ...}
//
// For an export that partially consumes the input:
// {"I", ...}
// {"L", ...}
// {"X", vm seed, inputAmount, asset id, anchor}
// {"L", vm seed, refdata}
// {"L", ...}
// {"L", ...}
// {"O", caller, outputid}
// {"R", ...}
// {"L", ...}
// {"F", ...}
func isExportTx(tx *bc.Tx, asset xdr.Asset, inputAmt int64, temp, exporter string, seqnum int64) bool {
	// The export transaction when we export the full input amount has seven operations, and when we export
	// part of the input and output the rest back to the exporter, it has ten operations
	if len(tx.Log) != 7 && len(tx.Log) != 10 {
		return false
	}
	if tx.Log[0][0].(txvm.Bytes)[0] != txvm.InputCode {
		return false
	}
	if tx.Log[1][0].(txvm.Bytes)[0] != txvm.LogCode {
		return false
	}
	if tx.Log[2][0].(txvm.Bytes)[0] != txvm.RetireCode {
		return false
	}
	if int64(tx.Log[2][2].(txvm.Int)) != inputAmt {
		return false
	}
	assetBytes, err := asset.MarshalBinary()
	if err != nil {
		return false
	}
	assetXDR, err := xdr.MarshalBase64(asset)
	if err != nil {
		return false
	}
	wantAssetID := txvm.AssetID(slidechain.IssueSeed[:], assetBytes)
	if !bytes.Equal(wantAssetID[:], tx.Log[2][3].(txvm.Bytes)) {
		return false
	}
	if tx.Log[3][0].(txvm.Bytes)[0] != txvm.LogCode {
		return false
	}
	ref := struct {
		AssetXDR string `json:"asset"`
		Temp     string `json:"temp"`
		Seqnum   int64  `json:"seqnum"`
		Exporter string `json:"exporter"`
	}{
		assetXDR,
		temp,
		seqnum,
		exporter,
	}
	refdata, err := json.Marshal(ref)
	if !bytes.Equal(refdata, tx.Log[3][2].(txvm.Bytes)) {
		return false
	}
	// Beyond this, the two transactions diverge but must either finalize
	// or output the remaining unconsumed input
	return true
}

func mustDecode(src string) []byte {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		log.Fatalf("error decoding %s: %s", src, err)
	}
	return bytes
}
