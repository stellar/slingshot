package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"net"
	"net/http"

	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	"github.com/interstellar/slingshot/slidechain"
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
		dbfile = flag.String("db", "slidechain.db", "path to db")
		url    = flag.String("horizon", "https://horizon-testnet.stellar.org", "horizon server url")
	)

	flag.Parse()

	db, err := sql.Open("sqlite3", *dbfile)
	if err != nil {
		log.Fatalf("error opening db: %s", err)
	}
	defer db.Close()
	c, err := slidechain.GetCustodian(ctx, db, *url)
	if err != nil {
		log.Fatal(err)
	}

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s, initial block ID %x", listener.Addr(), c.InitBlockHash.Bytes())

	http.Handle("/submit", c.S)
	http.HandleFunc("/get", c.S.Get)
	http.Serve(listener, nil)
}
