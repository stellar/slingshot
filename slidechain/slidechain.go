package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	"github.com/interstellar/starlight/worizon"
	_ "github.com/mattn/go-sqlite3"
)

var (
	initialBlock *bc.Block
	chain        *protocol.Chain
)

func main() {
	ctx := context.Background()

	var (
		addr   = flag.String("addr", "localhost:2423", "server listen address")
		dbfile = flag.String("db", "", "path to db")
		custID = flag.String("custid", "", "custodian's Stellar account ID")
	)

	flag.Parse()

	db, err := sql.Open("sqlite3", *dbfile)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	var cur worizon.Cursor // TODO: initialize from db (if applicable)

	wclient := worizon.NewClient(nil, nil)
	go func() {
		err := wclient.StreamTxs(ctx, *custID, cur, watchPegs(db))
		if err != nil {
			// TODO: error handling
		}
	}()

	heights := make(chan uint64)
	bs, err := newBlockStore(db, heights)
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

	// New blocks will be written to this multichan.
	w := multichan.New((*bc.Block)(nil))
	r := w.Reader()

	go watchExports(ctx, r)

	http.Handle("/submit", &submitter{w: w})
	http.HandleFunc("/get", get)
	http.HandleFunc("/import", doImport)
	http.Serve(listener, nil)
}

func httpErrf(w http.ResponseWriter, code int, msgfmt string, args ...interface{}) {
	http.Error(w, fmt.Sprintf(msgfmt, args...), code)
	log.Printf(msgfmt, args...)
}
