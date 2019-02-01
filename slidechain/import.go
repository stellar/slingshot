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
	amount, expMS int64,
	assetXDR, recipPubkey []byte,
) ([]byte, error) {
	// Put consume token program snapshot on the con stack and call it.
	consumeTokenSnapshot, err := consumeTokenProgSnapshot(c.InitBlockHash.Bytes(), assetXDR, recipPubkey, amount, expMS)
	if err != nil {
		return nil, errors.Wrap(err, "constructing consume token snapshot")
	}
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "x'%x' input put\n", consumeTokenSnapshot)            // arg stack: consumeTokenContract
	fmt.Fprintf(buf, "x'%x' contract call\n", importIssuanceProg)          // arg stack: sigchecker, issuedval, {recip}, quorum
	fmt.Fprintf(buf, "get get get splitzero\n")                            // con stack: quorum, {recip}, issuedval, zeroval; arg stack: sigchecker
	fmt.Fprintf(buf, "3 bury\n")                                           // con stack: zeroval, quorum, {recip}, issuedval; arg stack: sigchecker
	fmt.Fprintf(buf, "'' put\n")                                           // con stack: zeroval, quorum, {recip}, issuedval; sigchecker, refdata
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

	ch := make(chan struct{})
	go func() {
		c.imports.L.Lock()
		defer c.imports.L.Unlock()
		for {
			if ctx.Err() != nil {
				return
			}
			c.imports.Wait()
			ch <- struct{}{}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
		}

		var (
			amounts, expMSs               []int64
			nonceHashs, assetXDRs, recips [][]byte
		)
		const q = `SELECT nonce_hash, amount, asset_xdr, recipient_pubkey, expiration_ms FROM pegs WHERE imported=0`
		err := sqlutil.ForQueryRows(ctx, c.DB, q, func(nonceHash []byte, amount int64, assetXDR, recip []byte, expMS int64) {
			nonceHashs = append(nonceHashs, nonceHash)
			amounts = append(amounts, amount)
			assetXDRs = append(assetXDRs, assetXDR)
			recips = append(recips, recip)
			expMSs = append(expMSs, expMS)
		})
		if err == context.Canceled {
			return
		}
		if err != nil {
			log.Fatalf("querying pegs: %s", err)
		}
		for i, nonceHash := range nonceHashs {
			var (
				amount   = amounts[i]
				assetXDR = assetXDRs[i]
				recip    = recips[i]
				expMS    = expMSs[i]
			)
			err = c.doImport(ctx, nonceHash, amount, assetXDR, recip, expMS)
			if err != nil {
				if err == context.Canceled {
					return
				}
				log.Fatal(err)
			}
		}
	}
}

func (c *Custodian) doImport(ctx context.Context, nonceHash []byte, amount int64, assetXDR, recip []byte, expMS int64) error {
	log.Printf("doing import from tx with hash %x: %d of asset %x for recipient %x with expiration %d", nonceHash, amount, assetXDR, recip, expMS)

	importTxBytes, err := c.buildImportTx(amount, expMS, assetXDR, recip)
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
	log.Printf("assetID %x amount %d anchor %x\n", txresult.Issuances[0].Value.AssetID.Bytes(), txresult.Issuances[0].Value.Amount, txresult.Issuances[0].Value.Anchor)
	_, err = c.DB.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE nonce_hash = $1`, nonceHash)
	return errors.Wrapf(err, "setting imported=1 for tx with hash %x", nonceHash)
}
