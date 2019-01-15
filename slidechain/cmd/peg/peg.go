package main

import (
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"strings"

	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
	"i10r.io/worizon/xlm"
)

func main() {
	var (
		custodian  = flag.String("custodian", "", "Stellar account ID of custodian account")
		amount     = flag.String("amount", "", "amount to peg, in lumens")
		recipient  = flag.String("recipient", "", "hex-encoded txvm public key for the recipient of the pegged funds")
		seed       = flag.String("seed", "", "seed of Stellar source account")
		horizonURL = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon URL")
		basefee    = flag.Int("fee", 100, "tx base fee, in stroops")
	)
	flag.Parse()

	if *amount == "" {
		log.Fatal("must specify peg-in amount")
	}
	if *custodian == "" {
		log.Fatal("must specify custodian account")
	}
	if *recipient == "" {
		log.Fatal("must specify recipient")
	}
	if *seed == "" {
		log.Print("no seed specified, generating and funding a new account...")
		kp, err := keypair.Random()
		if err != nil {
			log.Fatal(err, "generating random keypair")
		}
		*seed = kp.Seed()
		resp, err := http.Get("https://friendbot.stellar.org/?addr=" + kp.Address())
		if err != nil {
			log.Fatal(err, "requesting friendbot lumens")
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("got bad status code %d requesting friendbot lumens", resp.StatusCode)
		}
		log.Printf("successfully funded %s", kp.Address())
	}

	xlmAmount, err := xlm.Parse(*amount)
	if err != nil {
		log.Fatal(err, "parsing payment amount")
	}

	var recipientPubkey [32]byte
	bytes, err := hex.DecodeString(*recipient)
	if err != nil {
		log.Fatal(err, "decoding recipient")
	}
	copy(recipientPubkey[:], bytes)

	hclient := &horizon.Client{
		URL:  strings.TrimRight(*horizonURL, "/"),
		HTTP: new(http.Client),
	}
	root, err := hclient.Root()
	if err != nil {
		log.Fatal(err, "getting horizon client root")
	}
	tx, err := b.Transaction(
		b.Network{Passphrase: root.NetworkPassphrase},
		b.SourceAccount{AddressOrSeed: *seed},
		b.AutoSequence{SequenceProvider: hclient},
		b.BaseFee{Amount: uint64(*basefee)},
		b.MemoHash{Value: xdr.Hash(recipientPubkey)},
		b.Payment(
			b.Destination{AddressOrSeed: *custodian},
			b.NativeAmount{Amount: xlmAmount.HorizonString()},
		),
	)
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
