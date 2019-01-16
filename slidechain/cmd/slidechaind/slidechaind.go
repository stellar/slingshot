package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"

	"slingshot/slidechain"

	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
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

	c, err := slidechain.NewCustodian(ctx, *dbfile, *url)
	if err != nil {
		log.Fatal(err)
	}
	defer c.DB.Close()

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("listening on %s, initial block ID %x", listener.Addr(), c.InitBlockHash.Bytes())

	c.Launch(ctx)

	http.Handle("/submit", c.S)
	http.HandleFunc("/get", c.S.Get)
	http.Serve(listener, nil)
}
