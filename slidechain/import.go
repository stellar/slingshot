package main

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"time"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txbuilder/standard"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
	"github.com/stellar/go/xdr"
)

// // Signer is the type of a function that produces a signature of a given message.
// type Signer func([]byte) ([]byte, error)

// buildImportTx builds the import transaction.
func (c *custodian) buildImportTx(
	blockid bc.Hash,
	custpubkeyhex string,
	amount int64,
	asset xdr.Asset,
) ([]byte, error) {
	// Push custodian pubkey, quorum size (1), asset code,
	// amount, exp, blockid onto the arg stack.
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "{x'%x'} put\n", c.pubkey)
	fmt.Fprintf(buf, "1 put\n") // fixed quorum size, since only 1 signer
	assetBytes, err := asset.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "getting asset bytes")
	}
	fmt.Fprintf(buf, "x'%x' put\n", assetBytes)
	fmt.Fprintf(buf, "x'%d' put\n", amount)
	exp := (time.Now().Add(time.Minute*5).UnixNano() / int64(time.Millisecond))
	fmt.Fprintf(buf, "x'%d' put\n", exp)
	fmt.Fprintf(buf, "x'%x' put\n", blockid.Bytes())

	// now arg stack is set up, empty con stack
	fmt.Fprintf(buf, "get get\n")        // con stack: blockid, exp
	fmt.Fprintf(buf, "nonce put\n")      // empty con stack, ..., nonce on arg stack
	fmt.Fprintf(buf, "x'%x'", issueProg) // empty con stack, arg stack: ..., sigchecker, issuedval

	// pay issued value
	fmt.Fprintf(buf, "get 0 split\n") // con stack: split issued value, zero issued val
	fmt.Fprintf(buf, "swap\n")        // con stack: zero issued val, split issued value
	fmt.Fprintf(buf, "get get get\n") // con stack: zero issued val, split issued val, sigchecker, {custpubkey}, 1
	fmt.Fprintf(buf, "4 reverse\n")   // con stack: zeroissuedval, 1, {custpubkey}, sigchecker, splitissuedval
	fmt.Fprintf(buf, "swap put put put put\n")
	fmt.Fprintf(buf, "x'%x' contract call\n", standard.PayToMultisigProg1)
	fmt.Fprintf(buf, "finalize\n")
	tx1, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling payment tx")
	}

	vm, err := txvm.Validate(tx1, 3, math.MaxInt64, txvm.StopAfterFinalize)
	if err != nil {
		return nil, errors.Wrap(err, "computing transaction ID")
	}
	sig := ed25519.Sign(c.privkey, vm.TxID[:])
	buf = new(bytes.Buffer)
	fmt.Fprintf(buf, "get x'%x' put put call\n", sig)
	tx2, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling signature section")
	}
	return append(tx1, tx2...), nil
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
