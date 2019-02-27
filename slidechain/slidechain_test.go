package slidechain

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	"github.com/interstellar/slingshot/slidechain/stellar"
	"github.com/interstellar/slingshot/slidechain/store"
	"github.com/interstellar/starlight/worizon/xlm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
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
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	withTestServer(ctx, t, func(ctx context.Context, _ *sql.DB, _ *submitter, server *httptest.Server, _ *protocol.Chain) {
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
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
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
		log.Printf("testing asset %s", tt.assetType)
		stellarAsset := makeAsset(tt.assetType, tt.code, tt.issuer)
		assetXDR, err := stellarAsset.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		withTestServer(ctx, t, func(ctx context.Context, db *sql.DB, s *submitter, server *httptest.Server, chain *protocol.Chain) {
			r := s.w.Reader()
			defer r.Dispose()

			c := &Custodian{
				imports:       sync.NewCond(new(sync.Mutex)),
				S:             s,
				DB:            db,
				privkey:       custodianPrv,
				InitBlockHash: chain.InitialBlockHash,
			}
			// Without a successful pre-peg-in TxVM tx, the initial input in the import tx will fail.
			log.Println("building and submitting pre-peg-in tx...")
			expMS := int64(bc.Millis(time.Now().Add(10 * time.Minute)))
			prepegTx, err := BuildPrepegTx(c.InitBlockHash.Bytes(), assetXDR, testRecipPubKey, 1, expMS)
			if err != nil {
				t.Fatal("could not build pre-peg-in tx")
			}
			_, err = c.S.submitTx(ctx, prepegTx)
			if err != nil {
				t.Fatal("could not submit pre-peg-in tx")
			}
			err = c.S.waitOnTx(ctx, prepegTx.ID, r)
			if err != nil {
				t.Fatal("unsuccessfully waited on pre-peg-in tx hitting txvm")
			}
			log.Println("pre-peg-in tx hit the txvm chain...")
			ready := make(chan struct{})
			go c.importFromPegIns(ctx, ready)
			<-ready
			nonceHash := UniqueNonceHash(c.InitBlockHash.Bytes(), expMS)
			_, err = db.Exec("INSERT INTO pegs (nonce_hash, amount, asset_xdr, recipient_pubkey, nonce_expms, stellar_tx) VALUES ($1, 1, $2, $3, $4, 1)", nonceHash[:], assetXDR, testRecipPubKey, expMS)
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
						t.Logf("found import tx %x", tx.Program)
						return
					}
				}
			}
		})
	}
}

func TestEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	// TODO(debnil): Test non-native assets.
	var tests = []struct {
		inputAmount  xlm.Amount
		exportAmount xlm.Amount
	}{
		{5 * xlm.Lumen, 5 * xlm.Lumen},
		{5 * xlm.Lumen, 3 * xlm.Lumen},
	}
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
		c := &Custodian{
			seed:          seed,
			AccountID:     *accountID,
			S:             s,
			DB:            db,
			hclient:       hclient,
			InitBlockHash: ch.InitialBlockHash,
			imports:       sync.NewCond(new(sync.Mutex)),
			exports:       sync.NewCond(new(sync.Mutex)),
			network:       root.NetworkPassphrase,
			privkey:       custodianPrv,
		}
		c.launch(ctx)

		exporterPub, exporterPrv, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatalf("error generating txvm recipient keypair: %s", err)
		}
		var exporterSeed [32]byte
		copy(exporterSeed[:], exporterPrv)
		exporter, err := keypair.FromRawSeed(exporterSeed)
		err = stellar.FundAccount(exporter.Address())
		if err != nil {
			t.Fatalf("error funding account %s: %s", exporter.Address(), err)
		}

		var exporterPubKeyBytes [32]byte
		copy(exporterPubKeyBytes[:], exporterPub)

		native := xdr.Asset{
			Type: xdr.AssetTypeAssetTypeNative,
		}
		nativeAssetBytes, err := native.MarshalBinary()
		if err != nil {
			t.Fatalf("error marshaling native asset to xdr: %s", err)
		}

		for _, tt := range tests {
			// Prepare Stellar account to peg-in funds and txvm account to receive funds.
			inputAmount := tt.inputAmount
			exportAmount := tt.exportAmount
			expMS := int64(bc.Millis(time.Now().Add(10 * time.Minute)))
			// Build, submit, and wait on pre-peg-in TxVM tx.
			prepegTx, err := BuildPrepegTx(c.InitBlockHash.Bytes(), nativeAssetBytes, exporterPubKeyBytes[:], int64(inputAmount), expMS)
			if err != nil {
				t.Fatal("could not build pre-peg-in tx")
			}
			r, err := c.S.submitTx(ctx, prepegTx)
			if err != nil {
				t.Fatal("could not submit pre-peg-in tx")
			}
			err = c.S.waitOnTx(ctx, prepegTx.ID, r)
			if err != nil {
				t.Fatal("unsuccessfully waited on pre-peg-in tx hitting txvm")
			}
			uniqueNonceHash := UniqueNonceHash(c.InitBlockHash.Bytes(), expMS)
			err = c.insertPegIn(ctx, uniqueNonceHash[:], exporterPubKeyBytes[:], expMS)
			if err != nil {
				t.Fatal("could not record peg")
			}

			// Build transaction to peg-in funds.
			pegInTx, err := stellar.BuildPegInTx(exporter.Address(), uniqueNonceHash, inputAmount.HorizonString(), "", "", c.AccountID.Address(), hclient)
			if err != nil {
				t.Fatalf("error building peg-in tx: %s", err)
			}
			succ, err := stellar.SignAndSubmitTx(hclient, pegInTx, exporter.Seed())
			if err != nil {
				t.Fatalf("error signing and submitting tx: %s", err)
			}
			t.Logf("successfully submitted peg-in tx: id %s, ledger %d", succ.Hash, succ.Ledger)

			// Check to verify import.
			var anchor []byte
			found := false
			for {
				item, ok := r.Read(ctx)
				if !ok {
					t.Fatal("cannot read a block")
				}
				block := item.(*bc.Block)
				for _, tx := range block.Transactions {
					if isImportTx(tx, int64(inputAmount), nativeAssetBytes, exporterPub) {
						t.Logf("found import tx %x", tx.Program)
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
			t.Log("submitting pre-export tx...")
			tempAddr, seqnum, err := SubmitPreExportTx(hclient, exporter, c.AccountID.Address(), native, int64(exportAmount))
			if err != nil {
				t.Fatalf("pre-submit tx error: %s", err)
			}
			t.Log("building export tx...")
			exportTx, err := BuildExportTx(ctx, native, int64(exportAmount), int64(inputAmount), tempAddr, anchor, exporterPrv, seqnum)
			if err != nil {
				t.Fatalf("error building retirement tx %s", err)
			}
			txbits, err := proto.Marshal(&exportTx.RawTx)
			if err != nil {
				t.Fatal(err)
			}

			// Submit the transaction and block until it's included in the txvm chain (or returns an error).
			t.Log("submitting and waiting on export tx on txvm...")
			req, err := http.NewRequest("POST", sv.URL+"/submit?wait=1", bytes.NewReader(txbits))
			if err != nil {
				log.Fatalf("error building request for latest block: %s", err)
			}
			req = req.WithContext(ctx)
			client := http.DefaultClient
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode/100 != 2 {
				t.Fatalf("status code %d from POST /submit?wait=1", resp.StatusCode)
			}

			// Check for successful retirement.
			t.Log("checking for successful retirement...")
			retire := make(chan struct{})
			go func() {
				var cur horizon.Cursor
				err := c.hclient.StreamTransactions(ctx, exporter.Address(), &cur, func(tx horizon.Transaction) {
					t.Logf("received tx: %s", tx.EnvelopeXdr)
					var env xdr.TransactionEnvelope
					err := xdr.SafeUnmarshalBase64(tx.EnvelopeXdr, &env)
					if err != nil {
						t.Fatal(err)
					}
					if env.Tx.SourceAccount.Address() != tempAddr {
						t.Log("source accounts don't match, skipping...")
						return
					}
					defer close(retire)
					if len(env.Tx.Operations) != 2 {
						t.Fatalf("too many operations got %d, want 2", len(env.Tx.Operations))
					}
					op := env.Tx.Operations[0]
					if op.Body.Type != xdr.OperationTypeAccountMerge {
						t.Fatalf("wrong operation type: got %s, want %s", op.Body.Type, xdr.OperationTypeAccountMerge)
					}
					if op.Body.Destination.Address() != exporter.Address() {
						t.Fatalf("wrong account merge destination: got %s, want %s", op.Body.Destination.Address(), exporter.Address())
					}
					op = env.Tx.Operations[1]
					if op.Body.Type != xdr.OperationTypePayment {
						t.Fatalf("wrong operation type: got %s, want %s", op.Body.Type, xdr.OperationTypePayment)
					}
					paymentOp := op.Body.PaymentOp
					if paymentOp.Destination.Address() != exporter.Address() {
						t.Fatalf("incorrect payment destination got %s, want %s", paymentOp.Destination.Address(), exporter.Address())
					}
					if paymentOp.Amount != xdr.Int64(exportAmount) {
						t.Fatalf("got incorrect payment amount %d, want %d", paymentOp.Amount, exportAmount)
					}
					if paymentOp.Asset.Type != xdr.AssetTypeAssetTypeNative {
						t.Fatalf("got incorrect payment asset %s, want lumens", paymentOp.Asset.String())
					}
				})
				if err != nil {
					t.Fatalf("error streaming from Horizon: %s", err)
				}
			}()

			select {
			case <-ctx.Done():
				t.Fatal("context timed out: no peg-out tx seen")
			case <-retire:
			}
			// Check for successful post-peg-out txvm tx.
			// We first split off the difference between inputAmt and exportAmt.
			// Then, we split off the zero-value for finalize, creating the retire anchor.
			retireAnchor1 := txvm.VMHash("Split2", anchor)
			retireAnchor := txvm.VMHash("Split1", retireAnchor1[:])
			found = false
			for {
				item, ok := r.Read(ctx)
				if !ok {
					t.Fatal("cannot read a block")
				}
				block := item.(*bc.Block)
				for _, tx := range block.Transactions {
					if isPostPegOutTx(tx, native, int64(exportAmount), tempAddr, exporter.Address(), int64(seqnum), retireAnchor[:], exporterPubKeyBytes[:]) {
						t.Logf("found post-peg-out tx %x", tx.Program)
						found = true
						break
					}
				}
				if found == true {
					break
				}
			}
		}
	})
}

// Expected log is:
//   {"I", ...}
//   {"A", contextID, amount, assetID, anchor}
//   {"L", ...}
//   {"O", caller, outputID}
//   {"F", ...}
func isImportTx(tx *bc.Tx, amount int64, assetXDR []byte, recipPubKey ed25519.PublicKey) bool {
	if len(tx.Log) != 5 {
		return false
	}
	if tx.Log[0][0].(txvm.Bytes)[0] != txvm.InputCode {
		return false
	}
	if tx.Log[1][0].(txvm.Bytes)[0] != txvm.IssueCode {
		return false
	}
	if int64(tx.Log[1][2].(txvm.Int)) != amount {
		return false
	}
	wantAssetID := txvm.AssetID(importIssuanceSeed[:], assetXDR)
	if !bytes.Equal(wantAssetID[:], tx.Log[1][3].(txvm.Bytes)) {
		return false
	}
	issueAnchor := tx.Log[1][4].(txvm.Bytes)
	splitAnchor := txvm.VMHash("Split1", issueAnchor) // the anchor of the issued value after a zeroval is split off of it
	if tx.Log[2][0].(txvm.Bytes)[0] != txvm.LogCode {
		return false
	}
	if tx.Log[3][0].(txvm.Bytes)[0] != txvm.OutputCode {
		return false
	}

	b := new(txvmutil.Builder)
	standard.Snapshot(b, 1, []ed25519.PublicKey{recipPubKey}, amount, bc.NewHash(wantAssetID), splitAnchor[:], standard.PayToMultisigSeed1[:])
	snapshotBytes := b.Build()
	wantOutputID := txvm.VMHash("SnapshotID", snapshotBytes)
	if !bytes.Equal(wantOutputID[:], tx.Log[3][2].(txvm.Bytes)) {
		return false
	}
	// No need to test tx.Log[4], it has to be a finalize entry.
	return true
}

// isPostPegOutTx returns whether or not a txvm transaction matches the slidechain post-export tx format.
//
// Expected log is
// {"I", ...}
// {"X", ...}
// {"L", ...}
// {"N", ...}
// {"R", ...}
// {"F", ...}
func isPostPegOutTx(tx *bc.Tx, asset xdr.Asset, amount int64, tempAddr, exporter string, seqnum int64, anchor, pubkey []byte) bool {
	if len(tx.Log) != 6 {
		return false
	}
	if tx.Log[0][0].(txvm.Bytes)[0] != txvm.InputCode {
		return false
	}
	if tx.Log[1][0].(txvm.Bytes)[0] != txvm.RetireCode {
		return false
	}
	if tx.Log[2][0].(txvm.Bytes)[0] != txvm.LogCode {
		return false
	}
	if tx.Log[3][0].(txvm.Bytes)[0] != txvm.NonceCode {
		return false
	}
	if tx.Log[4][0].(txvm.Bytes)[0] != txvm.TimerangeCode {
		return false
	}
	if tx.Log[5][0].(txvm.Bytes)[0] != txvm.FinalizeCode {
		return false
	}
	assetXDR, err := asset.MarshalBinary()
	if err != nil {
		return false
	}
	ref := pegOut{
		AssetXDR: assetXDR,
		TempAddr: tempAddr,
		Seqnum:   seqnum,
		Exporter: exporter,
		Amount:   amount,
		Anchor:   anchor,
		Pubkey:   pubkey,
	}
	refdata, err := json.Marshal(ref)
	if !bytes.Equal(refdata, tx.Log[2][2].(txvm.Bytes)) {
		return false
	}
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
		w:             w,
		chain:         chain,
		initialBlock:  initialBlock,
		blockInterval: DefaultBlockInterval,
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
