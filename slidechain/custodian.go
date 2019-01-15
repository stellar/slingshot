package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"log"
	"net/http"
	"sync"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
)

const custodianPrvHex = "508c64dfa1522aba45219495bf484ee4d1edb6c2051bf2a4356b43b24084db1637235cf548300f400b9afd671b8f701175c6d2549b96415743ae61a58bb437d7"

var (
	custodianPrv = ed25519.PrivateKey(mustDecodeHex(custodianPrvHex))
	custodianPub = custodianPrv.Public().(ed25519.PublicKey)
)

type custodian struct {
	seed          string
	accountID     xdr.AccountId
	db            *sql.DB
	w             *multichan.W
	hclient       *horizon.Client
	imports       *sync.Cond
	exports       *sync.Cond
	network       string
	privkey       ed25519.PrivateKey
	initBlockHash bc.Hash
}

func custodianAccount(ctx context.Context, db *sql.DB, hclient *horizon.Client) (*xdr.AccountId, string, error) {
	var seed string
	err := db.QueryRow("SELECT seed FROM custodian").Scan(&seed)
	if err == sql.ErrNoRows {
		return makeNewCustodianAccount(ctx, db, hclient)
	}
	if err != nil {
		return nil, "", errors.Wrap(err, "reading seed from db")
	}

	kp, err := keypair.Parse(seed)
	if err != nil {
		return nil, "", errors.Wrap(err, "parsing keypair from seed")
	}
	log.Printf("using preexisting custodian account %s", kp.Address())

	var custAccountID xdr.AccountId
	err = custAccountID.SetAddress(kp.Address())
	return &custAccountID, seed, err
}

func makeNewCustodianAccount(ctx context.Context, db *sql.DB, hclient *horizon.Client) (*xdr.AccountId, string, error) {
	pair, err := keypair.Random()
	if err != nil {
		return nil, "", errors.Wrap(err, "generating new keypair")
	}

	log.Printf("seed: %s", pair.Seed())
	log.Printf("addr: %s", pair.Address())

	resp, err := http.Get("https://friendbot.stellar.org/?addr=" + pair.Address())
	if err != nil {
		return nil, "", errors.Wrap(err, "requesting lumens through friendbot")
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", errors.Wrap(err, "funding address through friendbot")
	}
	log.Println("account successfully funded")

	account, err := hclient.LoadAccount(pair.Address())
	if err != nil {
		return nil, "", errors.Wrap(err, "loading testnet account")
	}
	log.Printf("balances for account: %s", pair.Address())

	for _, balance := range account.Balances {
		if balance.Type == "native" {
			log.Printf("%s lumens", balance.Balance)
		} else {
			log.Printf("%s of %s", balance.Balance, balance.Asset.Code)
		}
	}

	_, err = db.Exec("INSERT INTO custodian (seed) VALUES ($1)", pair.Seed())
	if err != nil {
		return nil, "", errors.Wrapf(err, "storing new custodian account")
	}

	var custAccountID xdr.AccountId
	err = custAccountID.SetAddress(pair.Address())
	return &custAccountID, pair.Seed(), err
}

func mustDecodeHex(inp string) []byte {
	result, err := hex.DecodeString(inp)
	if err != nil {
		log.Fatal(err)
	}
	return result
}
