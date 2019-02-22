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

// PegIn contains the fields for a peg-in transaction in the database.
type PegIn struct {
	Amount      int64  `json:"amount"`
	AssetXDR    []byte `json:"asset_xdr"`
	RecipPubkey []byte `json:"recip_pubkey"`
	ExpMS       int64  `json:"exp_ms"`
}

// RecordPegIn records a peg-in transaction in the database.
// TODO(debnil): Make record RPC do pre-peg tx submission as well, instead of requiring a separate server round-trip first.
func (c *Custodian) RecordPegIn(w http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	var p PegIn
	err = json.Unmarshal(data, &p)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	nonceHash := UniqueNonceHash(c.InitBlockHash.Bytes(), p.ExpMS)
	ctx := req.Context()
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
