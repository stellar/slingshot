package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txbuilder"
	"github.com/chain/txvm/protocol/txbuilder/standard"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/protobuf/proto"
	_ "github.com/mattn/go-sqlite3"
)

func TestServer(t *testing.T) {
	withTestServer(context.Background(), t, func(ctx context.Context, _ *sql.DB, _ *submitter, server *httptest.Server) {
		resp, err := http.Get(server.URL + "/get")
		if err != nil {
			t.Fatalf("getting initial block from new server: %s", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode/100 != 2 {
			t.Fatalf("status %d getting initial block from new server", resp.StatusCode)
		}

		b1bytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("reading initial block from new server: %s", err)
		}
		b1 := new(bc.Block)
		err = b1.FromBytes(b1bytes)
		if err != nil {
			t.Fatalf("parsing initial block from new server: %s", err)
		}

		req, err := http.NewRequest("GET", server.URL+"/get?height=2", nil)
		if err != nil {
			t.Fatal(err)
		}

		shortCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()

		req = req.WithContext(shortCtx)
		_, err = server.Client().Do(req)
		if unwraperr(err) != context.DeadlineExceeded {
			fmt.Print(spew.Sdump(err))
			t.Fatalf("got error %v, want %s", err, context.DeadlineExceeded)
		}

		ch := make(chan *bc.Block)
		go func() {
			defer close(ch)

			req, err := http.NewRequest("GET", server.URL+"/get?height=2", nil)
			if err != nil {
				t.Logf("creating GET request: %s", err)
				return
			}

			shortCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()

			req = req.WithContext(shortCtx)

			resp, err := server.Client().Do(req)
			if err != nil {
				t.Log(err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode/100 != 2 {
				t.Logf("status code %d from GET request", resp.StatusCode)
				return
			}

			b2bytes, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				t.Logf("reading GET response body: %s", err)
				return
			}

			b2 := new(bc.Block)
			err = b2.FromBytes(b2bytes)
			if err != nil {
				t.Logf("deserializing block 2: %s", err)
				return
			}

			ch <- b2
		}()

		const prvHex = "87fc07bf5fa9707b4e3cf1f6344d8a4d405a17425918ca5372239ff9e349cbef7996118db4183b89177435e2e0cc21dcb36427e2b09f35a72eeed37fede470c8"
		prvBits, err := hex.DecodeString(prvHex)
		if err != nil {
			t.Fatal(err)
		}
		prv := ed25519.PrivateKey(prvBits)
		pub := prv.Public().(ed25519.PublicKey)

		tpl := txbuilder.NewTemplate(time.Now().Add(time.Minute), nil)
		tpl.AddIssuance(2, initialBlock.Hash().Bytes(), nil, 1, [][]byte{prv}, nil, []ed25519.PublicKey{pub}, 10, nil, nil)
		assetID := standard.AssetID(2, 1, []ed25519.PublicKey{pub}, nil)
		tpl.AddOutput(1, []ed25519.PublicKey{pub}, 10, bc.NewHash(assetID), nil, nil)
		tpl.Sign(ctx, func(_ context.Context, msg []byte, keyID []byte, path [][]byte) ([]byte, error) {
			return ed25519.Sign(prv, msg), nil
		})
		tx, err := tpl.Tx()
		if err != nil {
			t.Fatal(err)
		}
		txbits, err := proto.Marshal(&tx.RawTx)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = http.Post(server.URL+"/submit", "application/octet-stream", bytes.NewReader(txbits))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode/100 != 2 {
			t.Fatalf("status code %d from POST /submit", resp.StatusCode)
		}

		b2 := <-ch
		if b2 == nil {
			t.Fatal("GET of block 2 failed")
		}

		if len(b2.Transactions) != 1 {
			t.Fatalf("got %d transactions in block 2, want 1", len(b2.Transactions))
		}

		if !reflect.DeepEqual(b2.Transactions[0], tx) {
			t.Fatal("tx mismatch")
		}
	})
}

func TestImport(t *testing.T) {
	stellarAsset := xdr.Asset{Type: xdr.AssetTypeAssetTypeNative} // TODO(bobg): other cases with other asset types
	assetXDR, err := stellarAsset.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}

	withTestServer(context.Background(), t, func(ctx context.Context, db *sql.DB, s *submitter, server *httptest.Server) {
		r := s.w.Reader()
		c := &custodian{
			imports: sync.NewCond(new(sync.Mutex)),
			db:      db,
		}
		go c.importFromPegs(ctx, s)
		_, err := db.Exec("INSERT INTO pegs (txid, operation_num, amount, asset_xdr) VALUES ('txid', 1, 1, $1)", assetXDR)
		if err != nil {
			t.Fatal(err)
		}
		c.imports.Broadcast()
		for {
			item, ok := r.Read(ctx)
			if !ok {
				t.Fatal("cannot read a block")
			}
			block := item.(*bc.Block)
			for _, tx := range block.Transactions {
				if isImportTx(tx, 1, assetXDR, recipient) {
					// xxx
				}
			}
		}
	})
}

func withTestServer(ctx context.Context, t *testing.T, fn func(context.Context, *sql.DB, *submitter, *httptest.Server)) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	f, err := ioutil.TempFile("", "txvmbcd")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile := f.Name()
	f.Close()
	defer os.Remove(tmpfile)

	db, err := startdb(tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	heights := make(chan uint64)
	bs, err := newBlockStore(db, heights)
	if err != nil {
		t.Fatal(err)
	}

	initialBlock, err = bs.GetBlock(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}

	chain, err = protocol.NewChain(ctx, initialBlock, bs, heights)
	if err != nil {
		t.Fatal(err)
	}

	w := multichan.New((*bc.Block)(nil))
	s := &submitter{w: w}

	http.HandleFunc("/get", get)
	http.Handle("/submit", s)
	server := httptest.NewServer(nil)
	defer server.Close()

	fn(ctx, db, s, server)
}

func unwraperr(err error) error {
	err = errors.Root(err)
	if err, ok := err.(*url.Error); ok {
		return unwraperr(err.Err)
	}
	return err
}
