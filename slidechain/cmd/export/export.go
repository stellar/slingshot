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
	"github.com/chain/txvm/protocol/txvm"
	"github.com/golang/protobuf/proto"
	"github.com/interstellar/slingshot/slidechain"
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/interstellar/starlight/worizon/xlm"
	"github.com/pkg/errors"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
)

type checkFn func(tx *bc.Tx, asset xdr.Asset, inputAmt int64, temp, exporter string, seqnum int64, anchor, pubkey []byte) bool

func main() {
	var (
		prv         = flag.String("prv", "", "hex encoding of ed25519 key for txvm and Stellar account")
		amount      = flag.String("amount", "", "amount to export")
		anchor      = flag.String("anchor", "", "txvm anchor of input to consume")
		input       = flag.String("input", "", "total amount of input")
		slidechaind = flag.String("slidechaind", "http://127.0.0.1:2423", "url of slidechaind server")
		code        = flag.String("code", "", "asset code if exporting non-lumen Stellar asset")
		issuer      = flag.String("issuer", "", "issuer of asset if exporting non-lumen Stellar asset")
		bcidHex     = flag.String("bcid", "", "hex-encoded initial block ID")
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
	if *bcidHex == "" {
		log.Fatal("must specify initial block ID")
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
	anchorBytes := mustDecode(*anchor)
	var bcidBytes [32]byte
	_, err = hex.Decode(bcidBytes[:], []byte(*bcidHex))
	if err != nil {
		log.Fatal("decoding initial block id: ", err)
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
	tx, err := slidechain.BuildExportTx(ctx, asset, exportAmount, inputAmount, temp, anchorBytes, mustDecode(*prv), seqnum)
	if err != nil {
		log.Fatalf("error building export tx: %s", err)
	}
	pubkey := ed25519.PrivateKey(mustDecode(*prv)).Public().(ed25519.PublicKey)
	err = submitTxAndWait(ctx, tx, *slidechaind, checkFn(slidechain.IsExportTx), asset, inputAmount, temp, kp.Address(), int64(seqnum), anchorBytes, pubkey)
	if err != nil {
		log.Fatalf("error submitting export tx: %s", err)
	}
	log.Printf("successfully submitted export transaction: %x", tx.ID)

	// Call post-export smart contract
	retireAnchor1 := txvm.VMHash("Split2", anchorBytes)
	retireAnchor := txvm.VMHash("Split1", retireAnchor1[:])
	assetXDR, err := asset.MarshalBinary()
	if err != nil {
		log.Fatalf("error marshaling asset: %s", err)
	}
	peggedOut := 1 // hard-code tx success
	tx, err = slidechain.BuildPostExportTx(ctx, assetXDR, retireAnchor[:], bcidBytes[:], exportAmount, int64(seqnum), int64(peggedOut), kp.Address(), temp, pubkey)
	if err != nil {
		log.Fatalf("error building post-export tx: %s", err)
	}
	err = submitTxAndWait(ctx, tx, *slidechaind, checkFn(slidechain.IsPostExportTx), asset, exportAmount, temp, kp.Address(), int64(seqnum), retireAnchor[:], pubkey)
	if err != nil {
		log.Fatalf("error submitting post-export tx: %s", err)
	}
}

func mustDecode(src string) []byte {
	bytes, err := hex.DecodeString(src)
	if err != nil {
		log.Fatalf("error decoding %s: %s", src, err)
	}
	return bytes
}

func submitTxAndWait(ctx context.Context, tx *bc.Tx, slidechaind string, fn checkFn, asset xdr.Asset, amount int64, temp, exporter string, seqnum int64, anchor, pubkey []byte) error {
	// Marshal tx
	txbits, err := proto.Marshal(&tx.RawTx)
	if err != nil {
		return err
	}

	// Get latest block height
	resp, err := http.Get(slidechaind + "/get?height=0")
	if err != nil {
		return errors.Wrapf(err, "error getting latest block height")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("bad status code %d getting latest block height", resp.StatusCode)
	}
	block := new(bc.Block)
	bits, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errors.Wrapf(err, "error reading block from response body")
	}
	err = block.FromBytes(bits)
	if err != nil {
		return errors.Wrapf(err, "error unmarshaling block")
	}

	resp, err = http.Post(slidechaind+"/submit", "application/octet-stream", bytes.NewReader(txbits))
	if err != nil {
		return errors.Wrapf(err, "error submitting tx to slidechaind")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status code %d from POST /submit", resp.StatusCode)
	}
	client := http.DefaultClient

	for height := block.Height + 1; ; height++ {
		req, err := http.NewRequest("GET", fmt.Sprintf(slidechaind+"/get?height=%d", height), nil)
		if err != nil {
			return errors.Wrap(err, "error building request for latest block")
		}
		req = req.WithContext(ctx)
		resp, err = client.Do(req)
		if err != nil {
			return errors.Wrapf(err, "error getting block at height %d", height)
		}
		defer resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			return fmt.Errorf("bad status code %d getting latest block height", resp.StatusCode)
		}
		b := new(bc.Block)
		bits, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrap(err, "error reading block from response body")
		}
		err = b.FromBytes(bits)
		if err != nil {
			return errors.Wrap(err, "error unmarshaling block")
		}
		for _, checkTx := range b.Transactions {
			// Check for the appropriate type of tx
			if fn(checkTx, asset, amount, temp, exporter, seqnum, anchor, pubkey) {
				log.Println("export tx included in txvm chain")
				return nil
			}
		}
	}
}
