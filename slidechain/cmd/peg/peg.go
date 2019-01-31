package main

import (
	"bytes"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
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
	// TODO(debnil): Call DoPrepegTx here.

	hclient := &horizon.Client{
		URL:  strings.TrimRight(*horizonURL, "/"),
		HTTP: new(http.Client),
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
}

// DoPrepegTx builds, submits the pre-peg TxVM transaction, and waits for it to hit the chain.
// TODO(debnil): Check if any of this should be moved to slidechaind.
func DoPrepegTx(bcid, assetXDR []byte, amount, expMS int64, pubkey ed25519.PublicKey, slidechaind string) error {
	prepegTx, err := buildPrepegTx(bcid, assetXDR, amount, expMS, pubkey)
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

func buildPrepegTx(bcid, assetXDR []byte, amount, expMS int64, pubkey ed25519.PublicKey) (*bc.Tx, error) {
	nonceHash := slidechain.UniqueNonceHash(bcid, expMS)
	finalizeExpMS := int64(bc.Millis(time.Now().Add(9 * time.Minute)))
	buf := new(bytes.Buffer)
	// Set up pre-peg tx arg stack: asset, amount, zeroval, {pubkey}, quorum
	fmt.Fprintf(buf, "x'%x' put\n", assetXDR)
	fmt.Fprintf(buf, "%d put\n", amount)
	fmt.Fprintf(buf, "x'%x' put\n", nonceHash)
	fmt.Fprintf(buf, "{x'%x'} put\n", pubkey)
	fmt.Fprintf(buf, "1 put\n") // The signer quorum size of 1 is fixed.
	fmt.Fprintf(buf, "x'%x' %d nonce finalize\n", bcid, finalizeExpMS)
	tx, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling pre-peg tx")
	}
	_, err = txvm.Validate(tx, 3, math.MaxInt64)
	if err != nil {
		return nil, errors.Wrap(err, "validating pre-peg tx")
	}
	var runlimit int64
	prepegTx, err := bc.NewTx(tx, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return nil, errors.Wrap(err, "populating new pre-peg tx")
	}
	prepegTx.Runlimit = math.MaxInt64 - runlimit
	return prepegTx, nil
}

func submitPrepegTx(tx *bc.Tx, slidechaind string) error {
	prepegTxBits, err := proto.Marshal(&tx.RawTx)
	if err != nil {
		return errors.Wrap(err, "marshaling pre-peg tx")
	}
	resp, err := http.Post(slidechaind+"/submit?wait=1", "application/octet-stream", bytes.NewReader(prepegTxBits))
	if err != nil {
		return errors.Wrap(err, "submitting to slidechaind: %s")
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
		return errors.Wrap(err, "recording to slidechaind: %s")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return errors.New(fmt.Sprintf("status code %d from POST /record", resp.StatusCode))
	}
	log.Printf("successfully recorded peg for tx %x", txid)
	return nil
}
