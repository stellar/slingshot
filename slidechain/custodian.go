package slidechain

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/bobg/multichan"
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	"github.com/interstellar/slingshot/slidechain/net"
	"github.com/interstellar/slingshot/slidechain/store"
	"github.com/stellar/go/clients/horizon"
	"github.com/stellar/go/keypair"
	"github.com/stellar/go/xdr"
)

const custodianPrvHex = "508c64dfa1522aba45219495bf484ee4d1edb6c2051bf2a4356b43b24084db1637235cf548300f400b9afd671b8f701175c6d2549b96415743ae61a58bb437d7"

var (
	custodianPrv = ed25519.PrivateKey(mustDecodeHex(custodianPrvHex))
	custodianPub = custodianPrv.Public().(ed25519.PublicKey)
)

// Custodian manages a Slidechain custodian, responsible
// for importing pegged-in values and pegging out exported
// values.
type Custodian struct {
	seed    string
	hclient horizon.ClientInterface
	imports *sync.Cond
	exports *sync.Cond
	network string
	privkey ed25519.PrivateKey

	DB            *sql.DB
	S             *submitter
	InitBlockHash bc.Hash
	AccountID     xdr.AccountId
}

// GetCustodian returns a Custodian object, loading the preset
// account ID and seed from the db if it exists, otherwise generating
// a new keypair and funding the account.
func GetCustodian(ctx context.Context, db *sql.DB, horizonURL string, blockInterval time.Duration) (*Custodian, error) {
	c, err := newCustodian(ctx, db, hclient(horizonURL), blockInterval)
	if err != nil {
		return nil, err
	}
	c.launch(ctx)
	return c, nil
}

func newCustodian(ctx context.Context, db *sql.DB, hclient horizon.ClientInterface, blockInterval time.Duration) (*Custodian, error) {
	err := setSchema(db)
	if err != nil {
		return nil, errors.Wrap(err, "setting db schema")
	}

	root, err := hclient.Root()
	if err != nil {
		return nil, errors.Wrap(err, "getting horizon client root")
	}

	custAccountID, seed, err := custodianAccount(ctx, db, hclient)
	if err != nil {
		return nil, errors.Wrap(err, "creating/fetching custodian account")
	}

	heights := make(chan uint64)
	bs, err := store.New(db, heights)
	if err != nil {
		log.Fatal(err)
	}

	initialBlock, err := bs.GetBlock(ctx, 1)
	if err != nil {
		log.Fatal(err)
	}

	chain, err := protocol.NewChain(ctx, initialBlock, bs, heights)
	if err != nil {
		log.Fatal("initializing Chain: ", err)
	}
	_, err = chain.Recover(ctx)
	if err != nil {
		log.Fatal(err)
	}

	return &Custodian{
		seed:      seed,
		AccountID: *custAccountID,
		S: &submitter{
			w:             multichan.New((*bc.Block)(nil)),
			chain:         chain,
			initialBlock:  initialBlock,
			blockInterval: blockInterval,
		},
		DB:            db,
		hclient:       hclient,
		imports:       sync.NewCond(new(sync.Mutex)),
		exports:       sync.NewCond(new(sync.Mutex)),
		network:       root.NetworkPassphrase,
		privkey:       custodianPrv,
		InitBlockHash: initialBlock.Hash(),
	}, nil
}

func custodianAccount(ctx context.Context, db *sql.DB, hclient horizon.ClientInterface) (*xdr.AccountId, string, error) {
	var seed string
	err := db.QueryRow("SELECT seed FROM custodian").Scan(&seed)
	if err == sql.ErrNoRows {
		return makeNewCustodianAccount(ctx, db, hclient)
	}
	if err != nil {
		return nil, "", errors.Wrap(err, "reading seed from db")
	}

	kp, err := keypair.Parse(seed)
	if err != nil {
		return nil, "", errors.Wrap(err, "parsing keypair from seed")
	}
	log.Printf("using preexisting custodian account %s", kp.Address())

	var custAccountID xdr.AccountId
	err = custAccountID.SetAddress(kp.Address())
	return &custAccountID, seed, err
}

func makeNewCustodianAccount(ctx context.Context, db *sql.DB, hclient horizon.ClientInterface) (*xdr.AccountId, string, error) {
	pair, err := keypair.Random()
	if err != nil {
		return nil, "", errors.Wrap(err, "generating new keypair")
	}

	log.Printf("seed: %s", pair.Seed())
	log.Printf("addr: %s", pair.Address())

	resp, err := http.Get("https://friendbot.stellar.org/?addr=" + pair.Address())
	if err != nil {
		return nil, "", errors.Wrap(err, "requesting lumens through friendbot")
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("bad status code %d funding address through friendbot", resp.StatusCode)
	}
	log.Println("account successfully funded")

	account, err := hclient.LoadAccount(pair.Address())
	if err != nil {
		return nil, "", errors.Wrap(err, "loading testnet account")
	}
	log.Printf("balances for account: %s", pair.Address())

	for _, balance := range account.Balances {
		if balance.Type == "native" {
			log.Printf("%s lumens", balance.Balance)
		} else {
			log.Printf("%s of %s", balance.Balance, balance.Asset.Code)
		}
	}

	_, err = db.Exec("INSERT INTO custodian (seed) VALUES ($1)", pair.Seed())
	if err != nil {
		return nil, "", errors.Wrapf(err, "storing new custodian account")
	}

	var custAccountID xdr.AccountId
	err = custAccountID.SetAddress(pair.Address())
	return &custAccountID, pair.Seed(), err
}

// Account returns the Stellar account ID of the custodian.
func (c *Custodian) Account(w http.ResponseWriter, req *http.Request) {
	_, err := xdr.Marshal(w, c.AccountID)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	return
}

// launch kicks off the Custodian's long-running goroutines
// that stream txs, import, and export.
func (c *Custodian) launch(ctx context.Context) {
	pegouts := make(chan pegOut)
	go c.watchPegIns(ctx)
	go c.importFromPegIns(ctx, nil)
	go c.watchExports(ctx)
	go c.pegOutFromExports(ctx, pegouts)
	go c.watchPegOuts(ctx, pegouts)
}

func mustDecodeHex(inp string) []byte {
	result, err := hex.DecodeString(inp)
	if err != nil {
		log.Fatal(err)
	}
	return result
}

func setSchema(db *sql.DB) error {
	_, err := db.Exec(schema)
	return errors.Wrap(err, "creating db schema")
}

func hclient(url string) *horizon.Client {
	return &horizon.Client{
		URL:  strings.TrimRight(url, "/"),
		HTTP: new(http.Client),
	}
}
