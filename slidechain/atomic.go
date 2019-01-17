package main

import (
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/protocol/txvm"
)

const atomicGuaranteeSrc = `
                                             #  con stack       arg stack       log
                                             #  ---------       ---------       ---
                                             #                  zeroval, recip
        get get [drop get eq verify] output  #  recip, zeroval                  {"O", vm.caller, outputid}
`

var (
	atomicGuaranteeProg = mustAssemble(atomicGuaranteeSrc)
	atomicGuaranteeSeed = txvm.ContractSeed(atomicGuaranteeProg)
)

// InputAtomic writes txvm bytecode to b, calling the atomicity-guarantee contract
// to confirm that the desired recipient pubkey is present.
func InputAtomic(b *txvmutil.Builder, pubkey ed25519.PublicKey) {
	Snapshot(b, pubkey)
	b.Op(op.Input).Op(op.Call)
}

// Snapshot adds to b the snapshot of an atomicity-guarantee contract as it appears in the UTXO set.
// TODO(debnil): Add anchor parameter.
func Snapshot(b *txvmutil.Builder, pubkey ed25519.PublicKey) {
	b.Tuple(func(contract *txvmutil.TupleBuilder) {
		contract.PushdataByte(txvm.ContractCode)          // 'C'
		contract.PushdataBytes(atomicGuaranteeSeed[:])    // <atomic guarantee seed>
		contract.PushdataBytes(atomicGuaranteeProg)       // [<atomicity guarantee prog>]
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'S', pubkey}
			tup.PushdataByte(txvm.BytesCode)
			tup.Tuple(func(pktup *txvmutil.TupleBuilder) {
				pktup.PushdataBytes(pubkey)
			})
		})
		contract.Tuple(func(tup *txvmutil.TupleBuilder) {
			tup.PushdataByte(txvm.ValueCode)
			tup.PushdataInt64(0)
			// TODO(debnil): Add zero hex string and anchor.
		})
	})
}
