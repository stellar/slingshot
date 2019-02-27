package slidechain

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/http"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
	"github.com/interstellar/slingshot/slidechain/net"
)

// PrePegIn contains the fields to build a pre-peg-in TxVM tx and record the peg-in transaction in the database.
type PrePegIn struct {
	BcID        []byte `json:"bc_id"`
	Amount      int64  `json:"amount"`
	AssetXDR    []byte `json:"asset_xdr"`
	RecipPubkey []byte `json:"recip_pubkey"`
	ExpMS       int64  `json:"exp_ms"`
}

func buildPrePegInTx(bcid, assetXDR, recip []byte, amount, expMS int64) (*bc.Tx, error) {
	buf := new(bytes.Buffer)
	// Set up pre-peg tx arg stack: asset, amount, zeroval, {recip}, quorum
	fmt.Fprintf(buf, "x'%x' put\n", assetXDR)
	fmt.Fprintf(buf, "%d put\n", amount)
	fmt.Fprintf(buf, "x'%x' %d nonce 0 split put\n", bcid, expMS)
	fmt.Fprintf(buf, "{x'%x'} put\n", recip)
	fmt.Fprintf(buf, "1 put\n") // The signer quorum size of 1 is fixed.
	// Call create token contract.
	fmt.Fprintf(buf, "x'%x' contract call\n", createTokenProg)
	fmt.Fprintf(buf, "finalize\n")
	prog, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling pre-peg tx")
	}
	_, err = txvm.Validate(prog, 3, math.MaxInt64)
	if err != nil {
		return nil, errors.Wrap(err, "validating pre-peg tx")
	}
	var runlimit int64
	tx, err := bc.NewTx(prog, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return nil, errors.Wrap(err, "populating new pre-peg tx")
	}
	tx.Runlimit = math.MaxInt64 - runlimit
	return tx, nil
}

// DoPrePegIn builds, submits, and waits on the pre-peg-in transaction to TxVM, and records a peg-in in the database.
func (c *Custodian) DoPrePegIn(w http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	// Unmarshal request.
	var p PrePegIn
	err = json.Unmarshal(data, &p)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	// Build pre-peg-in transaction.
	tx, err := buildPrePegInTx(p.BcID, p.AssetXDR, p.RecipPubkey, p.Amount, p.ExpMS)
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
	nonceHash := uniqueNonceHash(c.InitBlockHash.Bytes(), p.ExpMS)
	err = c.insertPegIn(ctx, nonceHash[:], p.RecipPubkey, p.ExpMS)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	log.Printf("recorded peg for tx with nonce hash %x in db", nonceHash[:])
	w.Header().Set("Content-Type", "application/octet-stream")
	_, err = w.Write(nonceHash[:])
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
}

func (c *Custodian) insertPegIn(ctx context.Context, nonceHash, recip []byte, expMS int64) error {
	const q = `INSERT INTO pegs
		(nonce_hash, recipient_pubkey, nonce_expms)
		VALUES ($1, $2, $3)`
	_, err := c.DB.ExecContext(ctx, q, nonceHash, recip, expMS)
	return errors.Wrap(err, "inserting peg in db")
}
