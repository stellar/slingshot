package slidechain

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
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
	"github.com/chain/txvm/protocol/txbuilder/txresult"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang/protobuf/proto"
	"github.com/interstellar/slingshot/slidechain/store"
	_ "github.com/mattn/go-sqlite3"
	b "github.com/stellar/go/build"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
	"i10r.io/worizon/xlm"
)

func makeAsset(typ xdr.AssetType, code string, issuer string) xdr.Asset {
	var issuerAccountID xdr.AccountId
	issuerAccountID.SetAddress(issuer)
	byteArray := []byte(code)

	var asset xdr.Asset
	switch typ {
	case xdr.AssetTypeAssetTypeNative:
		asset, _ = xdr.NewAsset(typ, nil)
	case xdr.AssetTypeAssetTypeCreditAlphanum4:
		var codeArray [4]byte
		copy(codeArray[:], byteArray)
		asset, _ = xdr.NewAsset(typ, xdr.AssetAlphaNum4{AssetCode: codeArray, Issuer: issuerAccountID})
	case xdr.AssetTypeAssetTypeCreditAlphanum12:
		var codeArray [12]byte
		copy(codeArray[:], byteArray)
		asset, _ = xdr.NewAsset(typ, xdr.AssetAlphaNum12{AssetCode: codeArray, Issuer: issuerAccountID})
	}
	return asset
}

func TestServer(t *testing.T) {
	withTestServer(context.Background(), t, func(ctx context.Context, _ *sql.DB, _ *submitter, server *httptest.Server, _ *protocol.Chain) {
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
		tpl.AddIssuance(2, b1.Hash().Bytes(), nil, 1, [][]byte{prv}, nil, []ed25519.PublicKey{pub}, 10, nil, nil)
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

var testRecipPubKey = mustDecodeHex("cca6ae12527fcb3f8d5648868a757ebb085a973b0fd518a5580a6ee29b72f8c1")

const importTestAccountID = "GDSBCQO34HWPGUGQSP3QBFEXVTSR2PW46UIGTHVWGWJGQKH3AFNHXHXN"

func TestImport(t *testing.T) {
	var importtests = []struct {
		assetType xdr.AssetType
		code      string
		issuer    string
	}{
		{xdr.AssetTypeAssetTypeNative, "", ""},
		{xdr.AssetTypeAssetTypeCreditAlphanum4, "USD", importTestAccountID},
		{xdr.AssetTypeAssetTypeCreditAlphanum12, "USDUSD", importTestAccountID},
	}
	for _, tt := range importtests {
		t.Logf("testing asset %s", tt.assetType)
		stellarAsset := makeAsset(tt.assetType, tt.code, tt.issuer)
		assetXDR, err := stellarAsset.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		withTestServer(context.Background(), t, func(ctx context.Context, db *sql.DB, s *submitter, server *httptest.Server, chain *protocol.Chain) {
			r := s.w.Reader()
			defer r.Dispose()

			c := &Custodian{
				imports:       sync.NewCond(new(sync.Mutex)),
				S:             s,
				DB:            db,
				privkey:       custodianPrv,
				InitBlockHash: chain.InitialBlockHash,
			}
			go c.importFromPegs(ctx)
			_, err := db.Exec("INSERT INTO pegs (txid, operation_num, amount, asset_xdr, recipient_pubkey) VALUES ('txid', 1, 1, $1, $2)", assetXDR, testRecipPubKey)
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
					if isImportTx(tx, 1, assetXDR, testRecipPubKey) {
						log.Printf("found import tx %x", tx.Program)
						return
					}
				}
			}
		})
	}
}

func TestEndToEnd(t *testing.T) {
	// TODO(vniu): add timeout
	ctx := context.Background()
	withTestServer(ctx, t, func(ctx context.Context, db *sql.DB, s *submitter, sv *httptest.Server, ch *protocol.Chain) {
		hclient := &horizon.Client{
			URL:  "https://horizon-testnet.stellar.org",
			HTTP: new(http.Client),
		}
		root, err := hclient.Root()
		if err != nil {
			t.Fatalf("error getting horizon client root: %s", err)
		}
		accountID, seed, err := custodianAccount(ctx, db, hclient)
		if err != nil {
			t.Fatalf("error creating custodian account: %s", err)
		}
		c := &custodian{
			seed:          seed,
			accountID:     *accountID,
			s:             s,
			db:            db,
			hclient:       hclient,
			initBlockHash: ch.InitialBlockHash,
			imports:       sync.NewCond(new(sync.Mutex)),
			exports:       sync.NewCond(new(sync.Mutex)),
			network:       root.NetworkPassphrase,
			privkey:       custodianPrv,
		}
		// TODO(vniu): refactor custodian functions for cleaner testing logic
		go c.watchPegs(ctx)
		go c.importFromPegs(ctx)
		go c.watchExports(ctx)
		go c.pegOutFromExports(ctx)

		// Make account to send the peg-in funds
		kp, err := keypair.Random()
		if err != nil {
			t.Fatalf("error generating random keypair: %s", err)
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

		recipientPrvHex := "c4cea91a1a64f6b563f894bb0984be5d52b60aa269dc9522b1fafa2eaea3b4636e20edbee85f4ea267c7399d96649174c5fd25ab46caf9022dc43a8142dc234f"
		recipientPrv := ed25519.PrivateKey(mustDecodeHex(recipientPrvHex))
		recipientPubkey := recipientPrv.Public().(ed25519.PublicKey)
		amount := 5 * xlm.Lumen

		var recipientPubkeyBytes [32]byte
		copy(recipientPubkeyBytes[:], recipientPubkey)

		// TODO(vniu): test with non-Lumen assets

		// Build + submit transaction to peg-in funds
		// TODO(vniu): import this from the peg command
		pegInTx, err := b.Transaction(
			b.Network{Passphrase: root.NetworkPassphrase},
			b.SourceAccount{AddressOrSeed: kp.Address()},
			b.AutoSequence{SequenceProvider: hclient},
			b.BaseFee{Amount: 100},
			b.MemoHash{Value: xdr.Hash(recipientPubkeyBytes)},
			b.Payment(
				b.Destination{AddressOrSeed: c.accountID.Address()},
				b.NativeAmount{Amount: amount.HorizonString()},
			),
		)
		if err != nil {
			t.Fatalf("error building peg-in tx: %s", err)
		}
		txenv, err := pegInTx.Sign(kp.Seed())
		if err != nil {
			t.Fatalf("error signing tx: %s", err)
		}
		txstr, err := xdr.MarshalBase64(txenv.E)
		if err != nil {
			t.Fatalf("error marshaling tx to base64: %s", err)
		}
		succ, err := hclient.SubmitTransaction(txstr)
		if err != nil {
			t.Fatalf("error submitting tx: %s", err)
		}
		log.Printf("successfully submitted peg-in tx: id %s, ledger %d", succ.Hash, succ.Ledger)

		native := xdr.Asset{
			Type: xdr.AssetTypeAssetTypeNative,
		}
		nativeAssetBytes, err := native.MarshalBinary()
		if err != nil {
			t.Fatalf("error marshaling native asset to xdr: %s", err)
		}

		// Check to verify import
		var anchor []byte
		found := false
		for {
			r := c.s.w.Reader()
			item, ok := r.Read(ctx)
			if !ok {
				t.Fatal("cannot read a block")
			}
			block := item.(*bc.Block)
			for _, tx := range block.Transactions {
				if isImportTx(tx, int64(amount), nativeAssetBytes, recipientPubkey) {
					log.Printf("found import tx %x", tx.Program)
					found = true
					txresult := txresult.New(tx)
					anchor = txresult.Outputs[0].Value.Anchor
					break
				}
			}
			if found == true {
				break
			}
		}

		// Build + submit txvm transaction to retire funds
		refdata := []byte(fmt.Sprintf(`{"asset":"AAAAAA==","account":"%s"}`, kp.Address()))
		assetIDBytes := txvm.AssetID(issueSeed[:], nativeAssetBytes)
		assetID := bc.HashFromBytes(assetIDBytes[:])
		tpl := txbuilder.NewTemplate(time.Now().Add(time.Minute), nil)
		// tpl.AddInput(1, [][]byte{recipientPrv}, nil, []ed25519.PublicKey{recipientPubkey}, int64(amount), assetID, anchor, nil, 2)
		tpl.AddInput(1, [][]byte{recipientPrv}, nil, []ed25519.PublicKey{recipientPubkey}, int64(amount), assetID, anchor, nil, 2)
		tpl.AddRetirement(int64(amount), assetID, refdata)
		err = tpl.Sign(ctx, func(_ context.Context, msg []byte, prv []byte, path [][]byte) ([]byte, error) {
			return ed25519.Sign(recipientPrv, msg), nil
		})
		if err != nil {
			t.Fatalf("error signing retirement tx %s", err)
		}
		exportTx, err := tpl.Tx()
		if err != nil {
			t.Fatalf("error building retirement tx %s", err)
		}
		txbits, err := proto.Marshal(&exportTx.RawTx)
		if err != nil {
			t.Fatal(err)
		}
		resp, err = http.Post(sv.URL+"/submit", "application/octet-stream", bytes.NewReader(txbits))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode/100 != 2 {
			t.Fatalf("status code %d from POST /submit", resp.StatusCode)
		}

		// Check for successful retirement
	})
}

// Expected log is:
//   {"N", ...}
//   {"R", ...}
//   {"A", contextID, amount, assetID, anchor}
//   {"L", ...}
//   {"O", caller, outputID}
//   {"F", ...}
func isImportTx(tx *bc.Tx, amount int64, assetXDR []byte, recipPubKey ed25519.PublicKey) bool {
	if len(tx.Log) != 6 {
		return false
	}
	if tx.Log[0][0].(txvm.Bytes)[0] != txvm.NonceCode {
		return false
	}
	if tx.Log[1][0].(txvm.Bytes)[0] != txvm.TimerangeCode {
		return false
	}
	if tx.Log[2][0].(txvm.Bytes)[0] != txvm.IssueCode {
		return false
	}
	if int64(tx.Log[2][2].(txvm.Int)) != amount {
		return false
	}
	wantAssetID := txvm.AssetID(issueSeed[:], assetXDR)
	if !bytes.Equal(wantAssetID[:], tx.Log[2][3].(txvm.Bytes)) {
		return false
	}
	issueAnchor := tx.Log[2][4].(txvm.Bytes)
	splitAnchor := txvm.VMHash("Split1", issueAnchor) // the anchor of the issued value after a zeroval is split off of it
	if tx.Log[3][0].(txvm.Bytes)[0] != txvm.LogCode {
		return false
	}
	if tx.Log[4][0].(txvm.Bytes)[0] != txvm.OutputCode {
		return false
	}

	b := new(txvmutil.Builder)
	standard.Snapshot(b, 1, []ed25519.PublicKey{recipPubKey}, amount, bc.NewHash(wantAssetID), splitAnchor[:], standard.PayToMultisigSeed1[:])
	snapshotBytes := b.Build()
	wantOutputID := txvm.VMHash("SnapshotID", snapshotBytes)
	if !bytes.Equal(wantOutputID[:], tx.Log[4][2].(txvm.Bytes)) {
		return false
	}
	// No need to test tx.Log[5], it has to be a finalize entry.
	return true
}

func withTestServer(ctx context.Context, t *testing.T, fn func(context.Context, *sql.DB, *submitter, *httptest.Server, *protocol.Chain)) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	f, err := ioutil.TempFile("", "txvmbcd")
	if err != nil {
		t.Fatal(err)
	}
	tmpfile := f.Name()
	f.Close()
	defer os.Remove(tmpfile)

	db, err := sql.Open("sqlite3", tmpfile)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	err = setSchema(db)
	if err != nil {
		t.Fatal(err)
	}

	heights := make(chan uint64)
	bs, err := store.New(db, heights)
	if err != nil {
		t.Fatal(err)
	}

	initialBlock, err := bs.GetBlock(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}

	chain, err := protocol.NewChain(ctx, initialBlock, bs, heights)
	if err != nil {
		t.Fatal(err)
	}

	w := multichan.New((*bc.Block)(nil))
	s := &submitter{
		w:            w,
		chain:        chain,
		initialBlock: initialBlock,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/get", s.Get)
	mux.Handle("/submit", s)
	server := httptest.NewServer(mux)
	defer server.Close()

	fn(ctx, db, s, server, chain)
}

func unwraperr(err error) error {
	err = errors.Root(err)
	if err, ok := err.(*url.Error); ok {
		return unwraperr(err.Err)
	}
	return err
}
