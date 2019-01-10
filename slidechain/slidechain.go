package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bobg/multichan"
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

type custodian struct {
	seed      string
	accountID xdr.AccountId
	db        *sql.DB
	w         *multichan.W
	hclient   *horizon.Client
	imports   *sync.Cond
	exports   *sync.Cond
	network   string
}

func start(ctx context.Context, addr, dbfile, horizonURL string) (*custodian, error) {
	db, err := sql.Open("sqlite3", dbfile)
	if err != nil {
		return nil, errors.Wrap(err, "opening db")
	}
	err = setSchema(db)
	if err != nil {
		return nil, errors.Wrap(err, "creating schema")
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

	// TODO(vniu): set custodian account seed
	return &custodian{
		accountID: *custAccountID, // TODO(tessr): should this field be a pointer to an xdr.AccountID?
		db:        db,
		w:         multichan.New((*bc.Block)(nil)),
		hclient:   hclient,
		imports:   sync.NewCond(new(sync.Mutex)),
		exports:   sync.NewCond(new(sync.Mutex)),
		network:   root.NetworkPassphrase,
	}, nil
}

func main() {
	ctx := context.Background()

	var (
		addr          = flag.String("addr", "localhost:2423", "server listen address")
		dbfile        = flag.String("db", "slidechain.db", "path to db")
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

	initialBlockID := initialBlock.Hash()

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s, initial block ID %x", listener.Addr(), initialBlockID.Bytes())

	s := &submitter{w: c.w}

	// Start streaming txs, importing, and exporting
	go func() {
		for {
			err := c.hclient.StreamTransactions(ctx, *custID, &cur, c.watchPegs)
			if err != nil {
				log.Println("error streaming from horizon: ", err)
			}
			// Wait before retrying
			time.Sleep(1 * time.Second)
		}
	}()

	go func() {
		err := c.importFromPegs(ctx, s)
		if err != nil {
			log.Fatal("error importing from pegs: ", err)
		}
	}()

	go func() {
		err := c.watchExports(ctx)
		if err != nil {
			log.Fatal("error watching for export txs: ", err)
		}
	}()

	go func() {
		err := c.pegOutFromExports(ctx)
		if err != nil {
			log.Fatal("error pegging out from exports: ", err)
		}
	}()

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
