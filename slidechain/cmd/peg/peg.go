package main

import (
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/stellar/go/clients/horizon"
)

func main() {
	var (
		custodian  = flag.String("custodian", "", "Stellar account ID of custodian account")
		amount     = flag.String("amount", "", "amount to peg, in lumens")
		recipient  = flag.String("recipient", "", "hex-encoded txvm public key for the recipient of the pegged funds")
		seed       = flag.String("seed", "", "seed of Stellar source account")
		horizonURL = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon URL")
		code       = flag.String("code", "", "asset code for non-Lumen asset")
		issuer     = flag.String("issuer", "", "asset issuer for non-Lumen asset")
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

	hclient := &horizon.Client{
		URL:  strings.TrimRight(*horizonURL, "/"),
		HTTP: new(http.Client),
	}
	tx, err := stellar.BuildPegInTx(*seed, recipientPubkey, *amount, *code, *issuer, *custodian, hclient)
	if err != nil {
		log.Fatal(err, "building transaction")
	}
	succ, err := stellar.SignAndSubmitTx(hclient, tx, *seed)
	if err != nil {
		log.Fatal(err, "submitting peg-in tx")
	}
	log.Printf("successfully submitted peg-in tx hash %s on ledger %d", succ.Hash, succ.Ledger)
}
