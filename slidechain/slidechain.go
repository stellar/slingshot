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

const privkeyHexStr = "508c64dfa1522aba45219495bf484ee4d1edb6c2051bf2a4356b43b24084db1637235cf548300f400b9afd671b8f701175c6d2549b96415743ae61a58bb437d7"

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

func start(ctx context.Context, addr, dbfile, horizonURL string) (*custodian, error) {
	db, err := startdb(dbfile)
	if err != nil {
		return nil, errors.Wrap(err, "starting db")
	}

	hclient := &horizon.Client{
		URL:  strings.TrimRight(horizonURL, "/"),
		HTTP: new(http.Client),
	}

	root, err := hclient.Root()
	if err != nil {
		return nil, errors.Wrap(err, "getting horizon client root")
	}

	custAccountID, err := custodianAccount(ctx, db, hclient)
	if err != nil {
		return nil, errors.Wrap(err, "creating/fetching custodian account")
	}

	privkeyStr, err := hex.DecodeString(privkeyHexStr)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding custodian private key (hex)")
	}
	privkey := ed25519.PrivateKey([]byte(privkeyStr))

	// TODO(vniu): set custodian account seed
	return &custodian{
		accountID: *custAccountID, // TODO(tessr): should this field be a pointer to an xdr.AccountID?
		db:        db,
		w:         multichan.New((*bc.Block)(nil)),
		hclient:   hclient,
		imports:   sync.NewCond(new(sync.Mutex)),
		exports:   sync.NewCond(new(sync.Mutex)),
		network:   root.NetworkPassphrase,
		privkey:   privkey,
	}, nil
}

func startdb(dbfile string) (*sql.DB, error) {
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		return nil, errors.Wrap(err, "opening db")
	}
	err = setSchema(db)
	return db, errors.Wrap(err, "creating schema")
}

func main() {
	ctx := context.Background()

	var (
		addr   = flag.String("addr", "localhost:2423", "server listen address")
		dbfile = flag.String("db", "slidechain.db", "path to db")
		custID = flag.String("custid", "", "custodian's Stellar account ID")
		url    = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon server url")
	)

	flag.Parse()

	// Assemble issuance TxVM program for custodian.
	// TODO(debnil): Move this logic to the issueProgFmt declaration site.
	privkeyStr, err := hex.DecodeString(privkeyHexStr)
	if err != nil {
		log.Fatal("error decoding custodian private key (hex): ", err)
	}
	privkey := ed25519.PrivateKey([]byte(privkeyStr))
	pubkey, ok := privkey.Public().([]byte)
	if !ok {
		log.Fatal("error converting custodian public key to byteslice")
	}
	pubkeyHex := hex.EncodeToString(pubkey)
	issueProgSrc = fmt.Sprintf(issueProgFmt, pubkeyHex)
	issueProg, err = asm.Assemble(issueProgSrc)
	if err != nil {
		log.Fatal(err)
	}
	issueSeed = txvm.ContractSeed(issueProg)

	c, err := start(ctx, *addr, *dbfile, *url)
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
	go c.watchPegs(ctx)
	go c.importFromPegs(ctx, s)
	go c.watchExports(ctx)
	go c.pegOutFromExports(ctx)

	http.Handle("/submit", s)
	http.HandleFunc("/get", get)
	http.Serve(listener, nil)
}

func setSchema(db *sql.DB) error {
	_, err := db.Exec(schema)
	return errors.Wrap(err, "creating db schema")
}

func httpErrf(w http.ResponseWriter, code int, msgfmt string, args ...interface{}) {
	http.Error(w, fmt.Sprintf(msgfmt, args...), code)
	log.Printf(msgfmt, args...)
}
