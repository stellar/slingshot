package slidechain

import (
	"context"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/chain/txvm/errors"
	"github.com/golang/protobuf/proto"
	"github.com/interstellar/slingshot/slidechain/net"
)

// Peg is a peg, before being inserted into a Custodian DB.
// The below methods are necessary for Peg to implement Proto.message.
// TODO(debnil): Should we make all fields required for protobuf and/or json?
// TODO(debnil): Is this worth making a new file?
type Peg struct {
	Amount      int64  `protobuf:"varint,1,opt,name=amount" json:"amount,omitempty"`
	AssetXDR    []byte `protobuf:"bytes,2,opt,name=assetxdr" json:"assetxdr,omitempty"`
	RecipPubkey []byte `protobuf:"bytes,3,opt,name=recippubkey" json:"recippubkey,omitempty"`
	ExpMS       int64  `protobuf:"varint,4,opt,name=expms" json:"expms,omitempty"`
}

// Reset implements the Reset method.
func (m *Peg) Reset() { *m = Peg{} }

// String implements the String method.
func (m *Peg) String() string { return proto.CompactTextString(m) }

// ProtoMessage implements the ProtoMessage method.
func (*Peg) ProtoMessage() {}

// RecordPeg records a peg-in transaction in the database.
// TODO(debnil): Make record RPC do pre-peg tx submission as well, instead of requiring a separate server round-trip first.
func (c *Custodian) RecordPeg(w http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	var p Peg
	err = proto.Unmarshal(data, &p)
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
