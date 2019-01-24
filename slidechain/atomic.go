package slidechain

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
)

const (
	atomicGuaranteeImportSrc = `
                                             #  con stack       arg stack       log
                                             #  ---------       ---------       ---
        drop drop                            #  recip, zeroval
`

	atomicGuaranteePrePegSrcFmt = `
                                             #  con stack       arg stack       log
                                             #  ---------       ---------       ---
                                             #                  zeroval, recip
        get get [%s] output                  #  recip, zeroval                  {"O", vm.caller, outputid}
`
)

var (
	atomicGuaranteeImportProg = mustAssemble(atomicGuaranteeImportSrc)
	atomicGuaranteeImportSeed = txvm.ContractSeed(atomicGuaranteeImportProg)
	atomicGuaranteePrePegSrc  = fmt.Sprintf(atomicGuaranteePrePegSrcFmt, atomicGuaranteeImportSrc)
	atomicGuaranteePrePegProg = mustAssemble(atomicGuaranteePrePegSrc)
	atomicGuaranteePrePegSeed = txvm.ContractSeed(atomicGuaranteePrePegProg)
	zeroSeed                  [32]byte
)

// AtomicNonceHash generates a nonce hash for the atomicity-guarantee contract.
func AtomicNonceHash(bcid []byte, expMS int64) [32]byte {
	nonce := txvm.NonceTuple(zeroSeed[:], zeroSeed[:], bcid, expMS)
	return txvm.NonceHash(nonce)
}

// ImportAtomicGuarantee writes txvm bytecode to b, calling the atomicity-guarantee import contract
// to confirm that the desired recipient pubkey is present.
func (c *Custodian) ImportAtomicGuarantee(b *txvmutil.Builder, pubkey ed25519.PublicKey, expMS int64) {
	importAtomicGuaranteeSnapshot(b, pubkey, c.InitBlockHash.Bytes(), expMS)
	b.Op(op.Input).Op(op.Call)
}

// importAtomicGuaranteeSnapshot adds to b the snapshot of an atomicity-guarantee contract as it appears in the UTXO set.
// TODO(debnil): Convert to fprintf-assembly.
func importAtomicGuaranteeSnapshot(b *txvmutil.Builder, pubkey ed25519.PublicKey, bcid []byte, expMS int64) {
	nonceHash := AtomicNonceHash(bcid, expMS)
	b.Tuple(func(contract *txvmutil.TupleBuilder) {
		contract.PushdataByte(txvm.ContractCode)             // 'C'
		contract.PushdataBytes(atomicGuaranteeImportSeed[:]) // <atomic guarantee import seed>
		contract.PushdataBytes(atomicGuaranteeImportProg)    // [<atomicity guarantee import prog>]
		contract.Tuple(func(tup *txvmutil.TupleBuilder) {    // {'S', pubkey}
			tup.PushdataByte(txvm.BytesCode)
			tup.PushdataBytes(pubkey)
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'V', 0, assetID, anchor}
			tup.PushdataByte(txvm.ValueCode)
			tup.PushdataInt64(0)
			tup.PushdataBytes(zeroSeed[:])
			tup.PushdataBytes(nonceHash[:])
		})
	})
}

// buildPrepegTx calls the atomicity-guarantee pre-peg contract to test utxo uniqueness.
func (c *Custodian) buildPrepegTx(expMS int64, pubkey ed25519.PublicKey) ([]byte, error) {
	nonceHash := AtomicNonceHash(c.InitBlockHash.Bytes(), expMS)
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "x'%x' put\n", nonceHash)
	fmt.Fprintf(buf, "x'%x' put\n", pubkey)
	fmt.Fprintf(buf, "x'%x' contract call\n", atomicGuaranteePrePegProg)
	tx, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling pre-peg atomicity tx")
	}
	_, err = txvm.Validate(tx, 3, math.MaxInt64)
	if err != nil {
		return nil, errors.Wrap(err, "computing pre-peg atomicity tx ID")
	}
	return tx, nil
}

// DoPrePegTx builds and submits the pre-peg txvm transaction.
func (c *Custodian) DoPrePegTx(ctx context.Context, expMS int64, pubkey ed25519.PublicKey) error {
	prepegTxBytes, err := c.buildPrepegTx(expMS, pubkey)
	if err != nil {
		return errors.Wrap(err, "building pre-peg tx")
	}
	var runlimit int64
	prepegTx, err := bc.NewTx(prepegTxBytes, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return errors.Wrap(err, "computing pre-peg tx ID")
	}
	prepegTx.Runlimit = math.MaxInt64 - runlimit
	err = c.submitPrePegTx(ctx, prepegTx)
	if err != nil {
		return errors.Wrap(err, "submitting pre-peg tx and waiting")
	}
	log.Print("submitted pre-peg txvm tx and confirmed on-chain")
	return nil
}

func (c *Custodian) submitPrePegTx(ctx context.Context, prepegTx *bc.Tx) error {
	checkHeight := c.S.chain.Height() + 1
	err := c.S.submitTx(ctx, prepegTx)
	if err != nil {
		return errors.Wrap(err, "submitting pre-peg tx")
	}
	for {
		var b *bc.Block
		for i := 0; i < 10; i++ {
			b, err = c.S.chain.GetBlock(ctx, checkHeight)
			if err != nil {
				log.Printf("error getting block at height %d, retrying in 5s", checkHeight)
				time.Sleep(5 * time.Second)
			} else {
				break
			}
		}
		if err != nil {
			return errors.New(fmt.Sprintf("error getting block at height %d, exiting", checkHeight))
		}
		for _, tx := range b.UnsignedBlock.Transactions {
			if tx.ID == prepegTx.ID {
				return nil
			}
		}
		log.Printf("could not find tx with id %s in block at height %d; incrementing block height", prepegTx.ID, checkHeight)
		checkHeight++
	}
	return errors.New("pre-peg tx not found on txvm chain")
}
