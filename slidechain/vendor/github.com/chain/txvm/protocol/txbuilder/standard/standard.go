// Package standard implements standard txvm contracts for Sequence
// transactions.
package standard

import (
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
)

// VerifyTxID returns a program that verifies the txid matches the
// given value.
func VerifyTxID(txid [32]byte) []byte {
	var b txvmutil.Builder
	b.Op(op.TxID)
	b.PushdataBytes(txid[:])
	b.Op(op.Eq).Op(op.Verify)
	return b.Build()
}
