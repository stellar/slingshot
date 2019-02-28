package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/stellar/go/clients/horizon"

	"github.com/interstellar/slingshot/slidechain"
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/interstellar/starlight/worizon/xlm"
)

func main() {
	var (
		custodian   = flag.String("custodian", "", "Stellar account ID of custodian account")
		amount      = flag.String("amount", "", "amount to peg, in lumens")
		recipient   = flag.String("recipient", "", "hex-encoded txvm public key for the recipient of the pegged funds")
		seed        = flag.String("seed", "", "seed of Stellar source account")
		horizonURL  = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon URL")
		code        = flag.String("code", "", "asset code for non-Lumen asset")
		issuer      = flag.String("issuer", "", "asset issuer for non-Lumen asset")
		bcidHex     = flag.String("bcid", "", "hex-encoded initial block ID")
		slidechaind = flag.String("slidechaind", "http://127.0.0.1:2423", "url of slidechaind server")
	)
	flag.Parse()

	if *amount == "" {
		log.Fatal("must specify peg-in amount")
	}
	if *custodian == "" {
		log.Fatal("must specify custodian account")
	}
	if (*code == "" && *issuer != "") || (*code != "" && *issuer == "") {
		log.Fatal("must specify both code and issuer for non-Lumen asset")
	}
	if *bcidHex == "" {
		log.Fatal("must specify initial block ID")
	}
	if *recipient == "" {
		log.Print("no recipient specified, generating txvm keypair...")
		pubkey, privkey, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalf("error generating txvm keypair: %s", err)
		}
		*recipient = hex.EncodeToString(pubkey)
		log.Printf("pegging funds to keypair %x / %x", privkey, pubkey)
	}
	if *seed == "" {
		log.Print("no seed specified, generating and funding a new account...")
		kp := stellar.NewFundedAccount()
		*seed = kp.Seed()
	}

	var recipientPubkey [32]byte
	if len(*recipient) != 64 {
		log.Fatalf("invalid recipient length: got %d want 64", len(*recipient))
	}
	_, err := hex.Decode(recipientPubkey[:], []byte(*recipient))
	if err != nil {
		log.Fatal("decoding recipient: ", err)
	}
	var bcidBytes [32]byte
	_, err = hex.Decode(bcidBytes[:], []byte(*bcidHex))
	if err != nil {
		log.Fatal("decoding initial block id: ", err)
	}
	asset := stellar.NativeAsset()
	if *code != "" {
		asset, err = stellar.NewAsset(*code, *issuer)
		if err != nil {
			log.Fatalf("error creating asset from code %s and issuer %s: %s", *code, *issuer, err)
		}
	}

	// XDR scales down an amount unit of every asset by a factor of 10^7.
	// Thus, xlm.Parse works for both native and non-native assets.
	amountXLM, err := xlm.Parse(*amount)
	if err != nil {
		log.Fatal("parsing horizon string: ", err)
	}

	assetXDR, err := asset.MarshalBinary()
	if err != nil {
		log.Fatal("marshaling asset xdr: ", err)
	}
	expMS := int64(bc.Millis(time.Now().Add(10 * time.Minute)))
	nonceHash, err := doPrePegIn(bcidBytes[:], assetXDR, int64(amountXLM), expMS, recipientPubkey[:], *slidechaind)
	if err != nil {
		log.Fatal("doing pre-peg-in tx: ", err)
	}
	hclient := &horizon.Client{
		URL:  strings.TrimRight(*horizonURL, "/"),
		HTTP: new(http.Client),
	}
	tx, err := stellar.BuildPegInTx(*seed, nonceHash, *amount, *code, *issuer, *custodian, hclient)
	if err != nil {
		log.Fatal("building transaction: ", err)
	}
	succ, err := stellar.SignAndSubmitTx(hclient, tx, *seed)
	if err != nil {
		log.Fatal("submitting peg-in tx: ", err)
	}
	log.Printf("successfully submitted peg-in tx hash %s on ledger %d", succ.Hash, succ.Ledger)
}

// doPrePegIn calls the pre-peg-in Slidechain RPC.
// That RPC builds, submits, and waits for the pre-peg TxVM transaction and records the peg-in in the database.
func doPrePegIn(bcid, assetXDR []byte, amount, expMS int64, pubkey ed25519.PublicKey, slidechaind string) ([32]byte, error) {
	var nonceHash [32]byte
	p := slidechain.PrePegIn{
		BcID:        bcid,
		Amount:      amount,
		AssetXDR:    assetXDR,
		RecipPubkey: pubkey,
		ExpMS:       expMS,
	}
	pegBits, err := json.Marshal(&p)
	if err != nil {
		return nonceHash, errors.Wrap(err, "marshaling peg")
	}
	resp, err := http.Post(slidechaind+"/prepegin", "application/octet-stream", bytes.NewReader(pegBits))
	if err != nil {
		return nonceHash, errors.Wrap(err, "recording to slidechaind")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nonceHash, fmt.Errorf("status code %d from POST /prepegin", resp.StatusCode)
	}

	_, err = io.ReadFull(resp.Body, nonceHash[:])
	if err != nil {
		return nonceHash, errors.Wrap(err, "reading POST /prepegin response body")
	}
	return nonceHash, nil
}
