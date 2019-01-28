package standard

import (
	"fmt"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/asm"
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
)

// payToMultisigProgUnlock expects:
//   argument stack: [... spendrefdata]
//   contract stack: [... quorum {p1,...,p_n} value]
// It unlocks `value` (placing it on the arg stack) and defers a MultisigProgCheck.
const payToMultisigProgUnlockSrcFmt = `
	             # Contract stack                               Argument stack  Log
	             # [quorum {p1,...,p_n} value]                  [spendrefdata]  []
	get log      # [quorum {p1,...,p_n} value]                  []              [{"L", <cid>, spendrefdata}]
	anchor       # [quorum {p1,...,p_n} value anchor]           []              [{"L", <cid>, spendrefdata}]
	swap put     # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
	[%s]         # [quorum {p1,...,p_n} anchor <multisigprog>]  [value]         [{"L", <cid>, spendrefdata}]
	yield        # [quorum {p1,...,p_n} anchor]                 [value]         [{"L", <cid>, spendrefdata}]
`

var (
	payToMultisigProgUnlockSrc = fmt.Sprintf(payToMultisigProgUnlockSrcFmt, multisigProgCheckSrc)

	// payToMultisigProgUnlock is the byte-code version of the "unlock"
	// phase of the standard pay-to-multisig-program contract. (That
	// contract begins with a "lock" phase that ends with "output."
	// PayToMultisigProgUnlock is what runs after the contract is
	// rehydrated with "input.")
	payToMultisigProgUnlock = asm.MustAssemble(payToMultisigProgUnlockSrc)
)

// SpendMultisig writes txvm bytecode to b, spending a value
// previously locked with the standard pay-to-multisig-program
// contract.
func SpendMultisig(
	b *txvmutil.Builder,
	quorum int,
	pubkeys []ed25519.PublicKey,
	amount int64,
	assetID bc.Hash,
	anchor []byte,
	seed []byte, // PayToMultisigSeed1[:] or PayToMultisigSeed2[:]
) {
	Snapshot(b, quorum, pubkeys, amount, assetID, anchor, seed)
	b.Op(op.Input).Op(op.Call)
}

// Snapshot adds to b the snapshot of a pay-to-multisig-program contract as it appears in the UTXO set.
func Snapshot(b *txvmutil.Builder,
	quorum int,
	pubkeys []ed25519.PublicKey,
	amount int64,
	assetID bc.Hash,
	anchor []byte,
	seed []byte, // PayToMultisigSeed1[:] or PayToMultisigSeed2[:]
) {
	b.Tuple(func(contract *txvmutil.TupleBuilder) {
		contract.PushdataByte(txvm.ContractCode)          // 'C'
		contract.PushdataBytes(seed)                      // <seed>
		contract.PushdataBytes(payToMultisigProgUnlock)   // [<multisig unlock prog>]
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'Z', quorum}
			tup.PushdataByte(txvm.IntCode)
			tup.PushdataInt64(int64(quorum))
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'T', {p1,...,p_n}}
			tup.PushdataByte(txvm.TupleCode)
			tup.Tuple(func(pktup *txvmutil.TupleBuilder) {
				for _, pubkey := range pubkeys {
					pktup.PushdataBytes(pubkey)
				}
			})
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'V', amount, assetID, anchor}
			tup.PushdataByte(txvm.ValueCode)
			tup.PushdataInt64(amount)
			tup.PushdataBytes(assetID.Bytes())
			tup.PushdataBytes(anchor)
		})
	})
}
