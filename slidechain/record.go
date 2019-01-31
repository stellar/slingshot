package slidechain

import (
	"context"
	"io/ioutil"
	"net/http"

	"github.com/golang/protobuf/proto"
	"github.com/interstellar/slingshot/slidechain/net"
)

// Peg is a peg, before being inserted into a Custodian DB.
// The below methods are necessary for Peg to implement Proto.message.
// TODO(debnil): Should we make all fields required for protobuf and/or json?
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

// RecordPegs records a peg-in transaction in the database.
func (c *Custodian) RecordPegs(w http.ResponseWriter, req *http.Request) {
	data, err := ioutil.ReadAll(req.Body)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
	}
	var p Peg
	err = proto.Unmarshal(data, &p)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
	const q = `INSERT INTO pegs
					(nonce_hash, amount, asset_xdr, recipient_pubkey, expiration_ms)
					VALUES ($1, $2, $3, $4, $5)`
	nonceHash := UniqueNonceHash(c.InitBlockHash.Bytes(), p.ExpMS)
	ctx := context.Background()
	_, err = c.DB.ExecContext(ctx, q, nonceHash[:], p.Amount, p.AssetXDR, p.RecipPubkey, p.ExpMS)
	if err != nil {
		net.Errorf(w, http.StatusInternalServerError, "sending response: %s", err)
		return
	}
}
