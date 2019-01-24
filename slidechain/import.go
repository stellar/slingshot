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
	"github.com/chain/txvm/protocol/txvm/txvmutil"
	"github.com/stellar/go/xdr"
)

// buildImportTx builds the import transaction.
func (c *Custodian) buildImportTx(
	amount int64,
	assetXDR []byte,
	recipPubkey []byte,
	expMS int64,
) ([]byte, error) {
	buf := new(bytes.Buffer)
	// Call the atomicity guarantee import contract.
	b := new(txvmutil.Builder)
	c.ImportAtomicGuarantee(b, recipPubkey, expMS)
	// TODO(debnil): Inline inputAtomicGuarantee instructions here.
	fmt.Fprintf(buf, "x'%x' exec\n", b.Build())

	// Push asset code and amount onto the arg stack.
	fmt.Fprintf(buf, "x'%x' put\n", assetXDR)
	fmt.Fprintf(buf, "%d put\n", amount)

	// Arg stack is set up; con stack is empty.
	fmt.Fprintf(buf, "x'%x' %d\n", c.InitBlockHash.Bytes(), expMS) // con stack: blockid, exp
	fmt.Fprintf(buf, "nonce put\n")                                // empty con stack; ..., nonce on arg stack
	fmt.Fprintf(buf, "x'%x' contract call\n", issueProg)           // empty con stack; arg stack: ..., sigcheck, issuedval

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
		return nil, errors.Wrap(err, "computing payment tx ID")
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
				expMS    = expMSs[i]
				recip    = recips[i]
			)
			err = c.doImport(ctx, amount, nonceHash, assetXDR, recip, expMS)
			if err != nil {
				if err == context.Canceled {
					return
				}
				log.Fatal(err)
			}
		}
	}
}

func (c *Custodian) doImport(ctx context.Context, amount int64, nonceHash, assetXDR, recip []byte, expMS int64) error {
	log.Printf("doing import of tx with uniqueness hash %x: %d of asset %x for recipient %x with expiration time %d", nonceHash, amount, assetXDR, recip, expMS)

	importTxBytes, err := c.buildImportTx(amount, assetXDR, recip, expMS)
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
	_, err = c.DB.ExecContext(ctx, `UPDATE pegs SET imported=1 WHERE nonce_hash = $1`, nonceHash)
	return errors.Wrapf(err, "setting imported=1 for tx with uniqueness hash %x", nonceHash)
}

// RecordPegs records the pegs-in for a transaction.
// TODO(debnil): Create a new file for this method.
func (c *Custodian) RecordPegs(ctx context.Context, tx xdr.Transaction, recipientPubkey []byte, expMS int64) error {
	for _, op := range tx.Operations {
		if op.Body.Type != xdr.OperationTypePayment {
			continue
		}
		payment := op.Body.PaymentOp
		if !payment.Destination.Equals(c.AccountID) {
			continue
		}
		// This operation is a payment to the custodian's account - i.e., a peg.
		// We record it in the db.
		nonceHash := AtomicNonceHash(c.InitBlockHash.Bytes(), expMS)
		const q = `INSERT INTO pegs 
			(nonce_hash, amount, asset_xdr, recipient_pubkey, expiration_ms)
			VALUES ($1, $2, $3, $4, $5)`
		assetXDR, err := payment.Asset.MarshalBinary()
		if err != nil {
			return errors.Wrap(err, fmt.Sprintf("marshaling asset to XDR %s", payment.Asset.String()))
		}
		_, err = c.DB.ExecContext(ctx, q, nonceHash[:], payment.Amount, assetXDR, recipientPubkey, expMS)
		if err != nil {
			return errors.Wrap(err, "recording peg-in tx")
		}
	}
	return nil
}
