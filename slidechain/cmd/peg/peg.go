package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/golang/protobuf/proto"
	"github.com/interstellar/slingshot/slidechain"
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
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
		bcid        = flag.String("bcid", "", "initial block ID")
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
	if *bcid == "" {
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

	if _, err := strconv.ParseFloat(*amount, 64); err != nil {
		log.Printf("invalid amount string %s: %s", *amount, err)
	}

	var recipientPubkey [32]byte
	if len(*recipient) != 64 {
		log.Fatalf("invalid recipient length: got %d want 64", len(*recipient))
	}
	_, err := hex.Decode(recipientPubkey[:], []byte(*recipient))
	if err != nil {
		log.Fatal(err, "decoding recipient")
	}
	var bcidBytes [32]byte
	_, err = hex.Decode(bcidBytes[:], []byte(*bcid))
	if err != nil {
		log.Fatal(err, "decoding initial block id")
	}
	var asset xdr.Asset
	if *issuer != "" {
		var issuerID xdr.AccountId
		err = issuerID.SetAddress(*issuer)
		if err != nil {
			log.Fatal(err, "setting issuer ID")
		}
		err = asset.SetCredit(*code, issuerID)
		if err != nil {
			log.Fatal(err, "setting asset code and issuer")
		}
	} else {
		asset, err = xdr.NewAsset(xdr.AssetTypeAssetTypeNative, nil)
		if err != nil {
			log.Fatal(err, "setting native asset")
		}
	}

	assetXDR, err := asset.MarshalBinary()
	if err != nil {
		log.Fatal(err, "marshaling asset xdr")
	}
	amountInt, err := strconv.ParseInt(*amount, 10, 64)
	if err != nil {
		log.Fatal(err, "converting amount to int64")
	}
	expMS := int64(bc.Millis(time.Now().Add(10 * time.Minute)))
	err = DoPrepegTx(bcidBytes[:], assetXDR, amountInt, expMS, recipientPubkey[:], *slidechaind)
	if err != nil {
		log.Fatal(err, "doing pre-peg-in tx")
	}
	hclient := &horizon.Client{
		URL:  strings.TrimRight(*horizonURL, "/"),
		HTTP: new(http.Client),
	}
	nonceHash := slidechain.UniqueNonceHash(bcidBytes[:], expMS)
	tx, err := stellar.BuildPegInTx(*seed, recipientPubkey, nonceHash, *amount, *code, *issuer, *custodian, hclient)
	if err != nil {
		log.Fatal(err, "building transaction")
	}
	txenv, err := tx.Sign(*seed)
	if err != nil {
		log.Fatal(err, "signing transaction")
	}
	txstr, err := xdr.MarshalBase64(txenv.E)
	if err != nil {
		log.Fatal(err, "marshaling tx to base64")
	}
	succ, err := hclient.SubmitTransaction(txstr)
	if err != nil {
		log.Fatalf("%s: submitting tx %s", err, txstr)
	}
	log.Printf("successfully submitted peg-in tx hash %s on ledger %d", succ.Hash, succ.Ledger)
}

// DoPrepegTx builds, submits the pre-peg TxVM transaction, and waits for it to hit the chain.
func DoPrepegTx(bcid, assetXDR []byte, amount, expMS int64, pubkey ed25519.PublicKey, slidechaind string) error {
	prepegTx, err := slidechain.BuildPrepegTx(bcid, assetXDR, pubkey, amount, expMS)
	if err != nil {
		return errors.Wrap(err, "building pre-peg-in tx")
	}
	err = submitPrepegTx(prepegTx, slidechaind)
	if err != nil {
		return errors.Wrap(err, "submitting and waiting on pre-peg-in tx")
	}
	err = recordPeg(prepegTx.ID, assetXDR, amount, expMS, pubkey, slidechaind)
	if err != nil {
		return errors.Wrap(err, "recording peg")
	}
	return nil
}

func submitPrepegTx(tx *bc.Tx, slidechaind string) error {
	prepegTxBits, err := proto.Marshal(&tx.RawTx)
	if err != nil {
		return errors.Wrap(err, "marshaling pre-peg tx")
	}
	resp, err := http.Post(slidechaind+"/submit?wait=1", "application/octet-stream", bytes.NewReader(prepegTxBits))
	if err != nil {
		return errors.Wrap(err, "submitting to slidechaind")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New(fmt.Sprintf("status code %d from POST /submit", resp.StatusCode))
	}
	log.Printf("successfully submitted and waited on pre-peg-in tx %x", tx.ID)
	return nil
}

func recordPeg(txid bc.Hash, assetXDR []byte, amount, expMS int64, pubkey ed25519.PublicKey, slidechaind string) error {
	p := slidechain.Peg{
		Amount:      amount,
		AssetXDR:    assetXDR,
		RecipPubkey: pubkey,
		ExpMS:       expMS,
	}
	pegBits, err := proto.Marshal(&p)
	if err != nil {
		return errors.Wrap(err, "marshaling peg")
	}
	resp, err := http.Post(slidechaind+"/record", "application/octet-stream", bytes.NewReader(pegBits))
	if err != nil {
		return errors.Wrap(err, "recording to slidechaind")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New(fmt.Sprintf("status code %d from POST /record", resp.StatusCode))
	}
	log.Printf("successfully recorded peg for tx %x", txid.Bytes())
	return nil
}
