package stellar

import (
	"log"
	"net/http"

	"github.com/pkg/errors"
	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
)

// NewFundedAccount generates a random keypair, creates
// an account on the Stellar testnet, and gets friendbot
// funds for that account, returning the account keypair
func NewFundedAccount() *keypair.Full {
	kp, err := keypair.Random()
	if err != nil {
		log.Fatal(err, "generating random keypair")
	}
	resp, err := http.Get("https://friendbot.stellar.org/?addr=" + kp.Address())
	if err != nil {
		log.Fatal(err, "requesting friendbot lumens")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("got bad status code %d requesting friendbot lumens", resp.StatusCode)
	}
	log.Printf("successfully funded %s", kp.Address())
	return kp
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
	txenv, err := tx.Sign(seed)
	if err != nil {
		return errors.Wrap(err, "signing tx")
	}
	txstr, err := xdr.MarshalBase64(txenv.E)
	if err != nil {
		return errors.Wrap(err, "marshaling tx")
	}
	_, err = hclient.SubmitTransaction(txstr)
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
	txenv, err := tx.Sign(seed)
	if err != nil {
		return errors.Wrap(err, "signing tx")
	}
	txstr, err := xdr.MarshalBase64(txenv.E)
	if err != nil {
		return errors.Wrap(err, "marshaling tx")
	}
	_, err = hclient.SubmitTransaction(txstr)
	return err
}
