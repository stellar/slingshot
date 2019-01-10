package main

import (
	"bytes"
	"context"
	"fmt"
	"math"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/txvm/asm"
	"i10r.io/protocol/txbuilder/standard"
	"i10r.io/protocol/txvm"
	"i10r.io/protocol/txvm/txvmutil"
)

// Signer is the type of a function that produces a signature of a given message.
type Signer func([]byte) ([]byte, error)

// buildImportTx builds the import transaction.
// The contract stack is empty.
// The argument stack has the custodian pubkey, quorum size (1), asset code,
// amount, exp, blockid.
func buildImportTx(
	blockid string,
	exp int,
	custpubkey string,
	amount int,
	asset []byte,
	signer Signer,
) ([]byte, error) {
	b := new(txvmutil.Builder)
	b.PushdataBytes([]byte(custpubkey))
	b.PushdataInt64(1) // fixed quorum size, since only 1 signer
	b.PushdataBytes(asset)
	b.PushdataInt64(int64(amount))
	b.PushdataInt64(int64(exp))
	b.PushdataBytes([]byte(blockid))
	setupArgProg := b.Build()

	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "x'%x' exec\n", setupArgProg) // setup arg stack, empty con stack
	fmt.Fprintf(buf, "get get\n")                  // con stack: blockid, exp
	fmt.Fprintf(buf, "nonce put\n")                // empty con stack, nonce on arg stack
	tx1, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling issuance setup tx")
	}
	tx1 = append(tx1, issueProg...) // empty con stack, arg stack: ..., sigchecker, issuedval

	// pay issued value
	buf = new(bytes.Buffer)
	fmt.Fprintf(buf, "get 0 split\n") // con stack: split issued value, zero issued val
	fmt.Fprintf(buf, "2 reverse\n")   // con stack: zero issued val, split issued value
	fmt.Fprintf(buf, "get get get\n") // con stack: zero issued val, split issued val, sigchecker, {custpubkey}, 1
	fmt.Fprintf(buf, "4 reverse\n")   // con stack: zeroissuedval, 1, {custpubkey}, sigchecker, splitissuedval
	fmt.Fprintf(buf, "1 roll put put put put")
	// TODO(debnil): Check if we need an if-else here.
	fmt.Fprintf(buf, "x'%x' exec\n", standard.PayToMultisigProg1)
	tx2, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling payment tx")
	}
	tx2 = append(tx1, tx2...)

	vm, err := txvm.Validate(tx1, 3, math.MaxInt64, txvm.StopAfterFinalize)
	if err != nil {
		return nil, errors.Wrap(err, "computing transaction ID")
	}
	sig, err := signer(vm.TxID[:])
	if err != nil {
		return nil, errors.Wrap(err, "computing signature")
	}
	buf = new(bytes.Buffer)
	fmt.Fprintf(buf, "get x'%x' put put call\n", sig)
	tx3, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling signature section")
	}
	return append(tx2, tx3...), nil
}

func (c *custodian) importFromPegs(ctx context.Context, s *submitter) error {
	c.imports.L.Lock()
	defer c.imports.L.Unlock()
	for {
		c.imports.Wait()
		const q = `SELECT txid, txhash, operation_num, amount, asset FROM pegs WHERE imported=0`
		err := sqlutil.ForQueryRows(ctx, c.db, q, func(txid string, txhash []byte, operationNum, amount int, asset []byte) error {
			// TODO: import the specified row through issuance contract
			_, err := c.db.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE txid=$1`, txid)
			if err != nil {
				return err
			}
			return nil
		})
		return err
	}
}
