package stellar

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/pkg/errors"
	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
)

// NewFundedAccount generates a random keypair, creates
// an account on the Stellar testnet, and gets friendbot
// funds for that account, returning the account keypair
func NewFundedAccount() *keypair.Full {
	kp, err := keypair.Random()
	if err != nil {
		log.Fatal(err, "generating random keypair")
	}
	err = FundAccount(kp.Address())
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("successfully funded %s", kp.Address())
	return kp
}

// FundAccount gets friendbot funds for an account on the Stellar testnet
func FundAccount(address string) error {
	resp, err := http.Get("https://friendbot.stellar.org/?addr=" + address)
	if err != nil {
		return errors.Wrap(err, "requesting friendbot lumens")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return errors.Wrapf(err, "reading response from bad friendbot request %d", resp.StatusCode)
		}
		return fmt.Errorf("error funding address through friendbot. got bad status code %d, response %s", resp.StatusCode, body)
	}
	return nil
}

// IssueAsset issues an asset from the specified seed account
// to the destination account.
func IssueAsset(hclient *horizon.Client, seed, code, amount, destination string) error {
	kp, err := keypair.Parse(seed)
	if err != nil {
		return err
	}
	tx, err := b.Transaction(
		b.SourceAccount{AddressOrSeed: seed},
		b.TestNetwork,
		b.AutoSequence{SequenceProvider: hclient},
		b.Payment(
			b.Destination{AddressOrSeed: destination},
			b.CreditAmount{
				Code:   code,
				Issuer: kp.Address(),
				Amount: amount,
			},
		),
	)
	if err != nil {
		return errors.Wrap(err, "building tx")
	}
	_, err = SignAndSubmitTx(hclient, tx, seed)
	return err
}

// TrustAsset issues a trustline from the seed account for the specified
// asset code and issuer.
func TrustAsset(hclient *horizon.Client, seed, code, issuer string) error {
	tx, err := b.Transaction(
		b.SourceAccount{AddressOrSeed: seed},
		b.TestNetwork,
		b.AutoSequence{SequenceProvider: hclient},
		b.Trust(code, issuer),
	)
	if err != nil {
		return errors.Wrap(err, "building tx")
	}
	_, err = SignAndSubmitTx(hclient, tx, seed)
	return err
}
