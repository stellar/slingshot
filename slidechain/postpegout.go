package slidechain

import (
	"context"
	"encoding/json"
	"fmt"
	"math"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
	"github.com/stellar/go/xdr"
)

func (c *Custodian) doPostPegOut(ctx context.Context, p pegOut) error {
	var asset xdr.Asset
	err := asset.UnmarshalBinary(p.AssetXDR)
	if err != nil {
		return errors.Wrap(err, "unmarshaling asset xdr")
	}
	assetID := bc.NewHash(txvm.AssetID(importIssuanceSeed[:], p.AssetXDR))

	refdata, err := json.Marshal(p)
	if err != nil {
		return errors.Wrap(err, "marshaling reference data")
	}

	// The contract needs a non-zero selector to retire funds if the peg-out succeeded.
	// Else, it requires a zero selector so the funds are returned.
	var selector int64
	if p.State == pegOutOK {
		selector = 1
	}

	// Build post-peg-out contract.
	b := new(txvmutil.Builder)
	b.Tuple(func(contract *txvmutil.TupleBuilder) { // {'C', ...}
		contract.PushdataByte(txvm.ContractCode)
		contract.PushdataBytes(exportContract1Seed[:])
		contract.PushdataBytes(exportContract2Prog)
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'T', pubkey}
			tup.PushdataByte(txvm.TupleCode)
			tup.Tuple(func(pktup *txvmutil.TupleBuilder) {
				pktup.PushdataBytes(p.Pubkey)
			})
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'S', refdata}
			tup.PushdataByte(txvm.BytesCode)
			tup.PushdataBytes(refdata)
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'V', amount, assetID, anchor}
			tup.PushdataByte(txvm.ValueCode)
			tup.PushdataInt64(p.Amount)
			tup.PushdataBytes(assetID.Bytes())
			tup.PushdataBytes(p.Anchor)
		})
	})
	b.PushdataInt64(selector).Op(op.Put) // con stack: snapshot; arg stack: selector
	b.Op(op.Input).Op(op.Call)           // arg stack: sigchecker, zeroval
	b.Op(op.Get).Op(op.Finalize)         // arg stack: sigchecker

	// Check signature.
	prog1 := b.Build()
	vm, err := txvm.Validate(prog1, 3, math.MaxInt64, txvm.StopAfterFinalize)
	if err != nil {
		return errors.Wrap(err, "computing transaction ID")
	}
	sig := ed25519.Sign(c.privkey, vm.TxID[:])
	b.Op(op.Get).PushdataBytes(sig).Op(op.Put) // con stack: sigchecker; arg stack: sig
	b.Op(op.Call)

	// Build, submit, and wait for the post-peg-out tx to hit txvm.
	prog2 := b.Build()
	var runlimit int64
	tx, err := bc.NewTx(prog2, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return errors.Wrap(err, "making post-peg-out tx")
	}
	tx.Runlimit = math.MaxInt64 - runlimit
	r, err := c.S.submitTx(ctx, tx)
	if err != nil {
		return errors.Wrap(err, "submitting post-peg-out tx")
	}
	err = c.S.waitOnTx(ctx, tx.ID, r)
	if err != nil {
		return errors.Wrap(err, "waiting on post-peg-out tx to hit txvm")
	}
	// Delete relevant row from exports table.
	// TODO(debnil): Implement a mechanism to recover in case of a crash here.
	// Currently, the txvm funds will be retired or refunded, but the db will not be updated.
	result, err := c.DB.ExecContext(ctx, `DELETE FROM exports WHERE txid=$1`, p.TxID)
	if err != nil {
		return errors.Wrapf(err, "deleting export for tx %x", p.TxID)
	}
	numAffected, err := result.RowsAffected()
	if err != nil {
		return errors.Wrapf(err, "checking rows affected by exports delete query for txid %x", p.TxID)
	}
	if numAffected != 1 {
		return fmt.Errorf("got %d rows affected by exports delete query, want 1", numAffected)
	}
	return nil
}
