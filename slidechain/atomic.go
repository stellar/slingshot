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
                                             #                  recip, zeroval
        get get [drop get eq verify] output  #  zeroval, recip                  {"O", vm.caller, outputid}
`

var (
	atomicGuaranteeProg = mustAssemble(atomicGuaranteeSrc)
	atomicGuaranteeSeed = txvm.ContractSeed(atomicGuaranteeProg)
)

// InputAtomic writes txvm bytecode to b, calling the atomicity-guarantee contract
// to confirm that the desired recipient pubkey is present.
func InputAtomic(b *txvmutil.Builder, pubkey ed25519.PublicKey, seed []byte) {
	Snapshot(b, pubkey, seed)
	b.Op(op.Input).Op(op.Call)
}

// Snapshot adds to b the snapshot of an atomicity-guarantee contract as it appears in the UTXO set.
func Snapshot(b *txvmutil.Builder, pubkey ed25519.PublicKey, seed []byte) {
	b.Tuple(func(contract *txvmutil.TupleBuilder) {
		contract.PushdataByte(txvm.ContractCode)          // 'C'
		contract.PushdataBytes(seed)                      // <seed>
		contract.PushdataBytes(atomicGuaranteeProg)       // [<atomicity issuance prog>]
		contract.Tuple(func(tup *txvmutil.TupleBuilder) { // {'S', pubkey}
			tup.PushdataByte(txvm.BytesCode)
			tup.Tuple(func(pktup *txvmutil.TupleBuilder) {
				pktup.PushdataBytes(pubkey)
			})
		})
	})
}
