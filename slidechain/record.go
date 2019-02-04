package slidechain

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/chain/txvm/errors"
	"github.com/interstellar/slingshot/slidechain/net"
)

// RecordPeg records a peg-in transaction in the database.
// TODO(debnil): Make record RPC do pre-peg tx submission as well, instead of requiring a separate server round-trip first.
func (c *Custodian) RecordPeg(w http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	var p struct {
		Amount      int64  `json:"amount"`
		AssetXDR    []byte `json:"assetxdr"`
		RecipPubkey []byte `json:"recippubkey"`
		ExpMS       int64  `json:"expms"`
	}
	err = json.Unmarshal(data, &p)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	nonceHash := UniqueNonceHash(c.InitBlockHash.Bytes(), p.ExpMS)
	ctx := req.Context()
	err = c.insertPeg(ctx, nonceHash[:], p.AssetXDR, p.RecipPubkey, p.Amount, p.ExpMS)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	log.Printf("recorded peg for tx with nonce hash %x in db", nonceHash[:])
	return
}

func (c *Custodian) insertPeg(ctx context.Context, nonceHash, assetXDR, recip []byte, amount, expMS int64) error {
	const q = `INSERT INTO pegs
		(nonce_hash, amount, asset_xdr, recipient_pubkey, nonce_expms)
		VALUES ($1, $2, $3, $4, $5)`
	_, err := c.DB.ExecContext(ctx, q, nonceHash, amount, assetXDR, recip, expMS)
	if err != nil {
		return errors.Wrap(err, "inserting peg in db")
	}
	return nil
}
