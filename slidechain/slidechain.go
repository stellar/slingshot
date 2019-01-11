package main

import (
	"context"
	"database/sql"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/xdr"
)

var (
	initialBlock *bc.Block
	chain        *protocol.Chain
)

const privkeyHexStr string = "508c64dfa1522aba45219495bf484ee4d1edb6c2051bf2a4356b43b24084db1637235cf548300f400b9afd671b8f701175c6d2549b96415743ae61a58bb437d7"

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

func start(addr, dbfile, custID, horizonURL string) (*custodian, error) {
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		return nil, errors.Wrap(err, "error opening db")
	}

	hclient := &horizon.Client{
		URL:  strings.TrimRight(horizonURL, "/"),
		HTTP: new(http.Client),
	}

	root, err := hclient.Root()
	if err != nil {
		return nil, errors.Wrap(err, "error getting horizon client root")
	}

	var custAccountID xdr.AccountId
	err = custAccountID.SetAddress(custID)
	if err != nil {
		return nil, errors.Wrap(err, "error setting custodian account ID")
	}

	privkeyStr, err := hex.DecodeString(privkeyHexStr)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding custodian private key (hex)")
	}
	privkey := ed25519.PrivateKey([]byte(privkeyStr))

	// TODO(vniu): set custodian account seed
	return &custodian{
		accountID: custAccountID,
		db:        db,
		w:         multichan.New((*bc.Block)(nil)),
		hclient:   hclient,
		imports:   sync.NewCond(new(sync.Mutex)),
		exports:   sync.NewCond(new(sync.Mutex)),
		network:   root.NetworkPassphrase,
		privkey:   privkey,
	}, nil
}

func main() {
	ctx := context.Background()

	var (
		addr          = flag.String("addr", "localhost:2423", "server listen address")
		dbfile        = flag.String("db", "slidechain.db", "path to db")
		custID        = flag.String("custid", "", "custodian's Stellar account ID")
		url           = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon server url")
		custPubkeyHex = flag.String("custpubkey", "", "custodian txvm public key (hex string)")
	)

	flag.Parse()

	// Assemble issuance TxVM program for custodian.
	issueProgSrc = fmt.Sprintf(issueProgFmt, *custPubkeyHex)
	var err error
	issueProg, err = asm.Assemble(issueProgSrc)
	if err != nil {
		log.Fatal(err)
	}
	issueSeed = txvm.ContractSeed(issueProg)

	var cur horizon.Cursor // TODO: initialize from db (if applicable)

	c, err := start(*addr, *dbfile, *custID, *url)
	if err != nil {
		log.Fatal(err)
	}
	defer c.db.Close()

	heights := make(chan uint64)
	bs, err := newBlockStore(c.db, heights)
	if err != nil {
		log.Fatal(err)
	}

	initialBlock, err = bs.GetBlock(ctx, 1)
	if err != nil {
		log.Fatal(err)
	}

	chain, err = protocol.NewChain(ctx, initialBlock, bs, heights)
	if err != nil {
		log.Fatal("initializing Chain: ", err)
	}
	_, err = chain.Recover(ctx)
	if err != nil {
		log.Fatal(err)
	}

	c.initBlockHash = initialBlock.Hash()

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s, initial block ID %x", listener.Addr(), c.initBlockHash.Bytes())

	s := &submitter{w: c.w}

	// Start streaming txs, importing, and exporting
	go func() {
		err := c.hclient.StreamTransactions(ctx, *custID, &cur, c.watchPegs)
		if err != nil {
			// TODO: error handling
		}
	}()

	go func() {
		err := c.importFromPegs(ctx, s)
		if err != nil {
			// TODO(vniu): error handling
		}
	}()

	go c.watchExports(ctx)

	go func() {
		err := c.pegOutFromExports(ctx)
		if err != nil {
			// TODO(vniu): error handling
		}
	}()

	http.Handle("/submit", s)
	http.HandleFunc("/get", get)
	http.Serve(listener, nil)
}

func httpErrf(w http.ResponseWriter, code int, msgfmt string, args ...interface{}) {
	http.Error(w, fmt.Sprintf(msgfmt, args...), code)
	log.Printf(msgfmt, args...)
}
