package slidechain

import (
	"context"
	"encoding/json"
	"math"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	i10rjson "github.com/chain/txvm/encoding/json"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
	"github.com/stellar/go/xdr"
)

func (c *Custodian) doPostPegOut(ctx context.Context, assetXDR string, anchor, txid []byte, amount, seqnum int64, peggedOut pegOutState, exporter, temp string, pubkey []byte) error {
	var asset xdr.Asset
	err := xdr.SafeUnmarshalBase64(assetXDR, &asset)
	if err != nil {
		return errors.Wrap(err, "unmarshaling asset xdr")
	}
	assetBytes, err := asset.MarshalBinary()
	if err != nil {
		return errors.Wrap(err, "marshaling asset bytes")
	}
	assetID := bc.NewHash(txvm.AssetID(importIssuanceSeed[:], assetBytes))
	ref := pegOut{
		AssetXDR: assetXDR,
		Temp:     temp,
		Seqnum:   seqnum,
		Exporter: exporter,
		Amount:   amount,
		Anchor:   anchor,
		Pubkey:   pubkey,
	}
	refdata, err := json.Marshal(ref)
	if err != nil {
		return errors.Wrap(err, "marshaling reference data")
	}
	refdataHex := i10rjson.HexBytes(refdata)
	b := new(txvmutil.Builder)
	b.Tuple(func(contract *txvmutil.TupleBuilder) { // {'C', ...}
		contract.PushdataByte(txvm.ContractCode)
		contract.PushdataBytes(exportContract1Seed[:])
		contract.PushdataBytes(exportContract2Prog)
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'T', pubkey}
			tup.PushdataByte(txvm.TupleCode)
			tup.Tuple(func(pktup *txvmutil.TupleBuilder) {
				pktup.PushdataBytes(pubkey)
			})
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'V', amount, assetID, anchor}
			tup.PushdataByte(txvm.ValueCode)
			tup.PushdataInt64(amount)
			tup.PushdataBytes(assetID.Bytes())
			tup.PushdataBytes(anchor)
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'S', refdata}
			tup.PushdataByte(txvm.BytesCode)
			tup.PushdataBytes(refdataHex)
		})
	})
	b.PushdataInt64(int64(peggedOut)).Op(op.Put)                        // con stack: snapshot; arg stack: selector
	b.Op(op.Input).Op(op.Call)                                          // arg stack: sigchecker
	b.PushdataBytes(c.InitBlockHash.Bytes())                            // con stack: blockid; arg stack: sigchecker
	b.PushdataInt64(int64(bc.Millis(time.Now().Add(10 * time.Minute)))) // con stack: blockid, expmss; arg stack: sigchecker
	b.Op(op.Nonce).Op(op.Finalize)                                      // arg stack: sigchecker

	prog1 := b.Build()
	vm, err := txvm.Validate(prog1, 3, math.MaxInt64, txvm.StopAfterFinalize)
	if err != nil {
		return errors.Wrap(err, "computing transaction ID")
	}
	sig := ed25519.Sign(c.privkey, vm.TxID[:])
	b.Op(op.Get).PushdataBytes(sig).Op(op.Put) // con stack: sigchecker; arg stack: sig
	b.Op(op.Call)

	prog2 := b.Build()
	tx, err := bc.NewTx(prog2, 3, math.MaxInt64)
	if err != nil {
		return errors.Wrap(err, "making post-peg-out tx")
	}
	if err != nil {
		return errors.Wrap(err, "building post-peg-out tx")
	}
	r, err := c.S.submitTx(ctx, tx)
	if err != nil {
		return errors.Wrap(err, "submitting post-peg-out tx")
	}
	err = c.S.waitOnTx(ctx, tx.ID, r)
	if err != nil {
		return errors.Wrap(err, "waiting on post-peg-out tx to hit txvm")
	}
	_, err = c.DB.ExecContext(ctx, `DELETE FROM exports WHERE txid=$1`, txid)
	return errors.Wrapf(err, "deleting export for tx %x", txid)
}
