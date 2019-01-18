package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/stellar/go/clients/horizon"
)

var args []string

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	subcommand := os.Args[1]
	args = os.Args[2:]
	switch subcommand {
	case "new":
		kp := stellar.NewFundedAccount()
		log.Printf("seed: %s, address: %s", kp.Seed(), kp.Address())
	case "issue":
		var (
			fs          flag.FlagSet
			seed        string
			code        string
			amount      string
			destination string
		)
		fs.StringVar(&seed, "seed", "", "seed of the Stellar account issuing funds")
		fs.StringVar(&code, "code", "", "code of the issued asset")
		fs.StringVar(&amount, "amount", "", "amount of the asset to issue")
		fs.StringVar(&destination, "destination", "", "Stellar account to issue assets to")
		err := fs.Parse(args)
		if err != nil {
			log.Fatal(err)
		}
		err = stellar.IssueAsset(horizon.DefaultTestNetClient, seed, code, amount, destination)
		if err != nil {
			log.Fatal(err)
		}
	case "trust":
		var (
			fs     flag.FlagSet
			seed   string
			code   string
			issuer string
		)
		fs.StringVar(&seed, "seed", "", "seed of the Stellar account issuing trustline")
		fs.StringVar(&code, "code", "", "asset code of the asset to trust")
		fs.StringVar(&issuer, "issuer", "", "issuer account ID of the asset to trust")
		err := fs.Parse(args)
		if err != nil {
			log.Fatal(err)
		}
		err = stellar.TrustAsset(horizon.DefaultTestNetClient, seed, code, issuer)
		if err != nil {
			log.Fatal(err)
		}
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
	account SUBCOMMAND ...args...

	Available subcommands are: new, issue, trust.

	The new subcommand generates a new Stellar testnet account
	and obtains testnet funds. It will print out the seed and 
	address of the newly created account. The new subcommand
	takes no arguments.
	
	The issue subcommand issues a new asset on the Stellar testnet
	from the given account. 
	
	issue:
		-seed SEED			seed of the Stellar account issuing funds
		-code CODE			code of the issued asset
		-amount AMOUNT  	amount of the asset to issue
		-destination DEST	Stellar account to issue assets to 

	The trust subcommand issues a trustline from the given account for
	an asset on the Stellar testnet.

	trust:
		-seed SEED		seed of the Stellar account issuing trustline
		-code CODE		code of the asset to trust
		-issuer ISSUER	address of the asset issuer 
	`)
	os.Exit(1)
}
