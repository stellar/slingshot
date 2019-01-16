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

	"github.com/bobg/multichan"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stellar/go/clients/horizon"
)

var (
	initialBlock *bc.Block
	chain        *protocol.Chain
)

func start(ctx context.Context, dbfile, horizonURL string) (*custodian, error) {
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

	custAccountID, seed, err := custodianAccount(ctx, db, hclient)
	if err != nil {
		return nil, errors.Wrap(err, "creating/fetching custodian account")
	}

	return &custodian{
		seed:      seed,
		accountID: *custAccountID, // TODO(tessr): should this field be a pointer to an xdr.AccountID?
		s:         &submitter{w: multichan.New((*bc.Block)(nil))},
		db:        db,
		hclient:   hclient,
		imports:   sync.NewCond(new(sync.Mutex)),
		exports:   sync.NewCond(new(sync.Mutex)),
		network:   root.NetworkPassphrase,
		privkey:   custodianPrv,
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
		url    = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon server url")
	)

	flag.Parse()

	c, err := start(ctx, *dbfile, *url)
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

	// Start streaming txs, importing, and exporting
	go c.watchPegs(ctx)
	go c.importFromPegs(ctx)
	go c.watchExports(ctx)
	go c.pegOutFromExports(ctx)

	http.Handle("/submit", c.s)
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
