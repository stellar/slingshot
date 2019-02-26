package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/golang/protobuf/proto"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"

	"github.com/interstellar/slingshot/slidechain"
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/interstellar/starlight/worizon/xlm"
)

func main() {
	var (
		custodian = flag.String("custodian", "", "Stellar account ID of custodian account")
		amount    = flag.Int("amount", -1, "amount to peg, in lumens")
		recipient = flag.String("recipient", "", "hex-encoded txvm public key for the recipient of the pegged funds")
		// seed        = flag.String("seed", "", "seed of Stellar source account")
		horizonURL  = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon URL")
		code        = flag.String("code", "", "asset code for non-Lumen asset")
		issuer      = flag.String("issuer", "", "asset issuer for non-Lumen asset")
		bcidHex     = flag.String("bcid", "", "hex-encoded initial block ID")
		slidechaind = flag.String("slidechaind", "http://127.0.0.1:2423", "url of slidechaind server")
	)
	flag.Parse()

	if *amount == -1 {
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
	var (
		seed     [32]byte
		exporter *keypair.Full
	)
	if *recipient == "" {
		log.Print("no recipient specified, generating txvm keypair...")
		pubkey, privkey, err := ed25519.GenerateKey(nil)
		if err != nil {
			log.Fatalf("error generating txvm keypair: %s", err)
		}
		*recipient = hex.EncodeToString(pubkey)
		log.Printf("pegging funds to keypair %x / %x", privkey, pubkey)
		copy(seed[:], privkey)
		exporter, err = keypair.FromRawSeed(seed)
		if err != nil {
			log.Fatalf("error generating stellar account from seed %x: %s", seed, err)
		}
		err = stellar.FundAccount(exporter.Address())
		if err != nil {
			log.Fatalf("error funding account %s: %s", exporter.Address(), err)
		}
	}
	// if *seed == "" {
	// 	log.Print("no seed specified, generating and funding a new account...")
	// 	kp := stellar.NewFundedAccount()
	// 	*seed = kp.Seed()
	// }

	// if _, err := strconv.ParseFloat(*amount, 64); err != nil {
	// 	log.Printf("invalid amount string %s: %s", *amount, err)
	// }

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
	var asset xdr.Asset
	if *issuer != "" {
		var issuerID xdr.AccountId
		err = issuerID.SetAddress(*issuer)
		if err != nil {
			log.Fatal("setting issuer ID: ", err)
		}
		err = asset.SetCredit(*code, issuerID)
		if err != nil {
			log.Fatal("setting asset code and issuer: ", err)
		}
	} else {
		asset, err = xdr.NewAsset(xdr.AssetTypeAssetTypeNative, nil)
		if err != nil {
			log.Fatal("setting native asset: ", err)
		}
	}

	assetXDR, err := asset.MarshalBinary()
	if err != nil {
		log.Fatal("marshaling asset xdr: ", err)
	}
	// amountInt, err := strconv.ParseInt(*amount, 10, 64)
	// if err != nil {
	// 	log.Fatal("converting amount to int64: ", err)
	// }
	amountXLM := xlm.Amount(*amount) * xlm.Lumen
	expMS := int64(bc.Millis(time.Now().Add(10 * time.Minute)))
	err = doPrepegTx(bcidBytes[:], assetXDR, int64(amountXLM), expMS, recipientPubkey[:], *slidechaind)
	if err != nil {
		log.Fatal("doing pre-peg-in tx: ", err)
	}
	hclient := &horizon.Client{
		URL:  strings.TrimRight(*horizonURL, "/"),
		HTTP: new(http.Client),
	}
	nonceHash := slidechain.UniqueNonceHash(bcidBytes[:], expMS)
	tx, err := stellar.BuildPegInTx(exporter.Address(), nonceHash, amountXLM.HorizonString(), *code, *issuer, *custodian, hclient)
	if err != nil {
		log.Fatal("building transaction: ", err)
	}
	succ, err := stellar.SignAndSubmitTx(hclient, tx, exporter.Seed())
	if err != nil {
		log.Fatal("submitting peg-in tx: ", err)
	}
	log.Printf("successfully submitted peg-in tx hash %s on ledger %d", succ.Hash, succ.Ledger)
}

// DoPrepegTx builds, submits the pre-peg TxVM transaction, and waits for it to hit the chain.
func doPrepegTx(bcid, assetXDR []byte, amount, expMS int64, pubkey ed25519.PublicKey, slidechaind string) error {
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
		return fmt.Errorf("status code %d from POST /submit", resp.StatusCode)
	}
	log.Printf("successfully submitted and waited on pre-peg-in tx %x", tx.ID)
	return nil
}

func recordPeg(txid bc.Hash, assetXDR []byte, amount, expMS int64, pubkey ed25519.PublicKey, slidechaind string) error {
	p := slidechain.PegIn{
		Amount:      amount,
		AssetXDR:    assetXDR,
		RecipPubkey: pubkey,
		ExpMS:       expMS,
	}
	pegBits, err := json.Marshal(&p)
	if err != nil {
		return errors.Wrap(err, "marshaling peg")
	}
	resp, err := http.Post(slidechaind+"/record", "application/octet-stream", bytes.NewReader(pegBits))
	if err != nil {
		return errors.Wrap(err, "recording to slidechaind")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("status code %d from POST /record", resp.StatusCode)
	}
	log.Printf("successfully recorded peg for tx %x", txid.Bytes())
	return nil
}
