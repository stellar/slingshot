package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"flag"
	"log"
	"net/http"
	"slingshot/slidechain"
	"strconv"
	"strings"
	"time"
	"txvm/protocol/bc"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
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
		dbfile     = flag.String("db", "slidechain.db", "path to db")
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
	db, err := sql.Open("sqlite3", *dbfile)
	if err != nil {
		log.Fatalf("error opening db: %s", err)
	}
	defer db.Close()

	hclient := &horizon.Client{
		URL:  strings.TrimRight(*horizonURL, "/"),
		HTTP: new(http.Client),
	}
	ctx := context.Background()
	c, err := slidechain.GetCustodian(ctx, db, *horizonURL)
	if err != nil {
		log.Fatalf("error getting custodian: %s", err)
	}
	expMS := int64(bc.Millis(time.Now().Add(10 * time.Minute)))
	// TODO(debnil): Should we launch this concurrently and wait?
	err = c.DoPrePegTx(ctx, expMS, recipientPubkey[:])
	if err != nil {
		log.Fatalf("error with pre-peg tx: %s", err)
	}
	tx, err := stellar.BuildPegInTx(*seed, recipientPubkey, *amount, *code, *issuer, *custodian, hclient)
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
	for i, op := range txenv.E.Tx.Operations {
		if op.Body.Type != xdr.OperationTypePayment {
			continue
		}
		payment := op.Body.PaymentOp
		if !payment.Destination.Equals(c.AccountID) {
			continue
		}
		// This operation is a payment to the custodian's account - i.e., a peg.
		// We record it in the db.
		const q = `INSERT INTO pegs 
			(txid, operation_num, amount, asset_xdr, recipient_pubkey, expiration_ms)
			VALUES ($1, $2, $3, $4, $5, $6)`
		assetXDR, err := payment.Asset.MarshalBinary()
		if err != nil {
			log.Fatalf("error marshaling asset to XDR %s: %s", payment.Asset.String(), err)
		}
		_, err = c.DB.ExecContext(ctx, q, succ.Hash, i, payment.Amount, assetXDR, recipientPubkey, expMS)
		if err != nil {
			log.Fatal("error recording peg-in tx: ", err)
		}
	}
	log.Printf("successfully inserted peg with tx id %s into db", succ.Hash)
}
