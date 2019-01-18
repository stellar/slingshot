package slidechain

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math"

	"github.com/bobg/sqlutil"
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txbuilder/standard"
	"github.com/chain/txvm/protocol/txbuilder/txresult"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
)

// buildImportTx builds the import transaction.
func (c *Custodian) buildImportTx(
	amount int64,
	assetXDR []byte,
	recipPubkey []byte,
	exp int64,
) ([]byte, error) {
	buf := new(bytes.Buffer)
	// Call the atomicity guarantee contract.
	// TODO(debnil): Should we convert atomicGuaranteeSnapshot to fprintf-assembly for consistency?
	b := new(txvm.Builder)
	inputAtomicGuarantee(b, recipPubkey, c.InitBlockHash, exp)
	fmt.Fprintf(buf, "x'%x' contract call\n", b.Build())

	// Push asset code and amount onto the arg stack.
	fmt.Fprintf(buf, "x'%x' put\n", assetXDR)
	fmt.Fprintf(buf, "%d put\n", amount)

	// Arg stack is set up; empty con stack.
	fmt.Fprintf(buf, "x'%x' %d\n", c.InitBlockHash.Bytes(), exp) // con stack: blockid, exp
	fmt.Fprintf(buf, "nonce put\n")                              // empty con stack; ..., nonce on arg stack
	fmt.Fprintf(buf, "x'%x' contract call\n", issueProg)         // empty con stack; arg stack: ..., sigcheck, issuedval

	// Pay issued value.
	fmt.Fprintf(buf, "get splitzero\n")                                    // con stack: issuedval, zeroval; arg stack: sigcheck
	fmt.Fprintf(buf, "'' put\n")                                           // con stack: issuedval, zeroval; arg stack: sigcheck, refdata
	fmt.Fprintf(buf, "swap put\n")                                         // con stack: zeroval; arg stack: sigcheck, refdata, issuedval
	fmt.Fprintf(buf, "{x'%x'} put\n", recipPubkey)                         // con stack: zeroval; arg stack: sigcheck, refdata, issuedval, {recippubkey}
	fmt.Fprintf(buf, "1 put\n")                                            // con stack: zeroval; arg stack: sigcheck, refdata, issuedval, {recippubkey}, quorum
	fmt.Fprintf(buf, "x'%x' contract call\n", standard.PayToMultisigProg1) // con stack: zeroval; arg stack: sigcheck
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
	fmt.Fprintf(buf, "get x'%x' put call\n", sig) // check sig
	tx2, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling signature section")
	}
	return tx2, nil
}

func (c *Custodian) importFromPegs(ctx context.Context) {
	defer log.Print("importFromPegs exiting")

	c.imports.L.Lock()
	defer c.imports.L.Unlock()

	for {
		if err := ctx.Err(); err != nil {
			return
		}
		c.imports.Wait()

		var (
			txids             []string
			opNums            []int
			amounts           []int64
			assetXDRs, recips [][]byte
			exps              []int64
		)
		const q = `SELECT txid, operation_num, amount, asset_xdr, recipient_pubkey FROM pegs WHERE imported=0`
		err := sqlutil.ForQueryRows(ctx, c.DB, q, func(txid string, opNum int, amount int64, assetXDR, recip []byte, exp int64) {
			txids = append(txids, txid)
			opNums = append(opNums, opNum)
			amounts = append(amounts, amount)
			assetXDRs = append(assetXDRs, assetXDR)
			recips = append(recips, recip)
			exps = append(exps, exp)
		})
		if err == context.Canceled {
			return
		}
		if err != nil {
			log.Fatalf("querying pegs: %s", err)
		}
		for i, txid := range txids {
			var (
				opNum    = opNums[i]
				amount   = amounts[i]
				assetXDR = assetXDRs[i]
				recip    = recips[i]
				exp      = exps[i]
			)
			err = c.doImport(ctx, txid, opNum, amount, assetXDR, recip, exp)
			if err != nil {
				if err == context.Canceled {
					return
				}
				log.Fatal(err)
			}
		}
	}
}

func (c *Custodian) doImport(ctx context.Context, txid string, opNum int, amount int64, assetXDR, recip []byte, exp int64) error {
	log.Printf("doing import from tx %s, op %d: %d of asset %x for recipient %x with expiration time %d", txid, opNum, amount, assetXDR, recip, exp)

	importTxBytes, err := c.buildImportTx(amount, assetXDR, recip, exp)
	if err != nil {
		return errors.Wrap(err, "building import tx")
	}
	var runlimit int64
	importTx, err := bc.NewTx(importTxBytes, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return errors.Wrap(err, "computing transaction ID")
	}
	importTx.Runlimit = math.MaxInt64 - runlimit
	err = c.S.submitTx(ctx, importTx)
	if err != nil {
		return errors.Wrap(err, "submitting import tx")
	}
	txresult := txresult.New(importTx)
	log.Printf("asset id: %x", txresult.Issuances[0].Value.AssetID)
	log.Printf("output anchor: %x", txresult.Outputs[0].Value.Anchor)
	_, err = c.DB.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE txid = $1 AND operation_num = $2`, txid, opNum)
	return errors.Wrapf(err, "setting imported=1 for txid %s, operation %d", txid, opNum)
}
