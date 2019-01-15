package main

import (
	"flag"
	"log"
	"net/http"

	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
	"i10r.io/worizon/xlm"
)

func main() {
	var (
		basefee    = flag.Int("fee", 100, "tx base fee, in stroops")
		custodian  = flag.String("custodian", "", "Stellar account ID of custodian account")
		amount     = flag.Int("amount", 0, "amount to peg, in lumens")
		seed       = flag.String("seed", "", "seed of Stellar source account")
		horizonURL = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon URL")
	)
	flag.Parse()

	if *amount == 0 {
		log.Fatal("must specify peg-in amount")
	}
	if *custodian == "" {
		log.Fatal("must specify custodian account")
	}
	if *seed == "" {
		// No seed specified, must generate and fund a new account
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
	}

	hclient := &horizon.Client{
		URL: *horizonURL,
	}
	root, err := hclient.Root()
	if err != nil {
		log.Fatal(err, "getting horizon client root")
	}
	lumenAmount := xlm.Amount(*amount) * xlm.Lumen
	tx, err := b.Transaction(
		b.Network{Passphrase: root.NetworkPassphrase},
		b.SourceAccount{AddressOrSeed: *seed},
		b.AutoSequence{SequenceProvider: hclient},
		b.BaseFee{Amount: uint64(*basefee)},
		b.Payment(
			b.Destination{AddressOrSeed: *custodian},
			b.NativeAmount{Amount: lumenAmount.HorizonString()},
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
	_, err = hclient.SubmitTransaction(txstr)
	if err != nil {
		log.Fatalf("%s: submitting tx %s", err, txstr)
	}
	log.Print("successfully submitted peg-in tx")
}
