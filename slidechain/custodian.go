package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"

	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"

	"i10r.io/errors"
)

func custodianAccount(ctx context.Context, db *sql.DB, hclient *horizon.Client) (*xdr.AccountId, error) {
	var accountID string
	err := db.QueryRow("SELECT account_id FROM custodian_account").Scan(&accountID)
	if err == sql.ErrNoRows {
		return makeNewCustodianAccount(ctx, db, hclient)
	}

	if err != nil {
		return nil, err
	}

	log.Printf("using preexisting custodian account %s", accountID)

	var custAccountID xdr.AccountId
	err = custAccountID.SetAddress(accountID)
	return &custAccountID, err
}

func makeNewCustodianAccount(ctx context.Context, db *sql.DB, hclient *horizon.Client) (*xdr.AccountId, error) {
	pair, err := keypair.Random()
	if err != nil {
		return nil, errors.Wrap(err, "generating new keypair")
	}

	log.Printf("seed: %s", pair.Seed())
	log.Printf("addr: %s", pair.Address())

	resp, err := http.Get("https://friendbot.stellar.org/?addr=" + pair.Address())
	if err != nil {
		return nil, errors.Wrap(err, "requesting lumens through friendbod")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.Wrap(err, "funding address through friendbot")
	}
	log.Println("account successfully funded")

	account, err := hclient.LoadAccount(pair.Address())
	if err != nil {
		return nil, errors.Wrap(err, "loading testnet account")
	}
	fmt.Println("balances for account:", pair.Address())

	for _, balance := range account.Balances {
		if balance.Type == "native" {
			log.Printf("%s lumens", balance.Balance)
		} else {
			log.Printf("%s of %s", balance.Balance, balance.Asset.Code)
		}
	}

	_, err = db.Exec("INSERT OR IGNORE INTO custodian_account (account_id) VALUES ($1)", pair.Address())
	if err != nil {
		return nil, errors.Wrapf(err, "storing new custodian account")
	}

	var custAccountID xdr.AccountId
	err = custAccountID.SetAddress(pair.Address())
	return &custAccountID, err
}
