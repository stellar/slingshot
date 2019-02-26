package slidechain

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/golang/protobuf/proto"
	"github.com/interstellar/slingshot/slidechain/net"
)

// PegIn contains the fields for a peg-in transaction in the database.
type PegIn struct {
	Transaction []byte `json:"tx"`
	Amount      int64  `json:"amount"`
	AssetXDR    []byte `json:"asset_xdr"`
	RecipPubkey []byte `json:"recip_pubkey"`
	ExpMS       int64  `json:"exp_ms"`
}

// DoPegIn submits the pre-peg-in transaction to TxVM and records a peg-in transaction in the database.
// TODO(debnil): Make record RPC do pre-peg tx submission as well, instead of requiring a separate server round-trip first.
func (c *Custodian) DoPegIn(w http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	// Unmarshal peg-in.
	var p PegIn
	err = json.Unmarshal(data, &p)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	// Unmarshal pre-peg-in transaction.
	var rawTx bc.RawTx
	err = proto.Unmarshal(p.Transaction, &rawTx)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	tx, err := bc.NewTx(rawTx.Program, rawTx.Version, rawTx.Runlimit)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	// Submit pre-peg-in transaction and wait on success.
	ctx := req.Context()
	r, err := c.S.submitTx(ctx, tx)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	err = c.S.waitOnTx(ctx, tx.ID, r)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
	}
	// Record peg in database.
	nonceHash := UniqueNonceHash(c.InitBlockHash.Bytes(), p.ExpMS)
	err = c.insertPegIn(ctx, nonceHash[:], p.RecipPubkey, p.ExpMS)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	log.Printf("recorded peg for tx with nonce hash %x in db", nonceHash[:])
	return
}

func (c *Custodian) insertPegIn(ctx context.Context, nonceHash, recip []byte, expMS int64) error {
	const q = `INSERT INTO pegs
		(nonce_hash, recipient_pubkey, nonce_expms)
		VALUES ($1, $2, $3)`
	_, err := c.DB.ExecContext(ctx, q, nonceHash, recip, expMS)
	return errors.Wrap(err, "inserting peg in db")
}
