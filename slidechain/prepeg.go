package slidechain

import (
	"bytes"
	"fmt"
	"math"
	"time"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
)

// BuildPrepegTx builds the pre-peg-in TxVM transaction to create a uniqueness token.
func BuildPrepegTx(bcid, assetXDR, recip []byte, amount, expMS int64) (*bc.Tx, error) {
	buf := new(bytes.Buffer)
	// Set up pre-peg tx arg stack: asset, amount, zeroval, {recip}, quorum
	fmt.Fprintf(buf, "x'%x' put\n", assetXDR)
	fmt.Fprintf(buf, "%d put\n", amount)
	fmt.Fprintf(buf, "x'%x' %d nonce put\n", bcid, expMS)
	fmt.Fprintf(buf, "{x'%x'} put\n", recip)
	fmt.Fprintf(buf, "1 put\n") // The signer quorum size of 1 is fixed.
	// Call create token contract.
	fmt.Fprintf(buf, "x'%x' contract call\n", createTokenProg)
	// TODO(debnil): Split the zeroval from the nonce above for performance reasons.
	// We did not do that right now, because it results in a mismatched anchor on the import side.
	finalizeExpMS := int64(bc.Millis(time.Now().Add(9 * time.Minute)))
	fmt.Fprintf(buf, "x'%x' %d nonce finalize\n", bcid, finalizeExpMS)
	tx, err := asm.Assemble(buf.String())
	if err != nil {
		return nil, errors.Wrap(err, "assembling pre-peg tx")
	}
	_, err = txvm.Validate(tx, 3, math.MaxInt64)
	if err != nil {
		return nil, errors.Wrap(err, "validating pre-peg tx")
	}
	var runlimit int64
	prepegTx, err := bc.NewTx(tx, 3, math.MaxInt64, txvm.GetRunlimit(&runlimit))
	if err != nil {
		return nil, errors.Wrap(err, "populating new pre-peg tx")
	}
	prepegTx.Runlimit = math.MaxInt64 - runlimit
	return prepegTx, nil
}
