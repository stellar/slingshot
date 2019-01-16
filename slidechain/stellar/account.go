package stellar

import (
	"log"
	"net/http"

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
