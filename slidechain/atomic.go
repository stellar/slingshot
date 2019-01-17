package main

import (
	"time"
	"txvm/protocol/txbuilder/standard"

	"github.com/chain/txvm/protocol/bc"
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
func InputAtomic(b *txvmutil.Builder, pubkey ed25519.PublicKey, bcid []byte) {
	Snapshot(b, pubkey, bcid)
	b.Op(op.Input).Op(op.Call)
}

// Snapshot adds to b the snapshot of an atomicity-guarantee contract as it appears in the UTXO set.
func Snapshot(b *txvmutil.Builder, pubkey ed25519.PublicKey, bcid []byte) {
	contractSeed := standard.AssetContractSeed[3] // Hardcoded TxVM version ID.
	nonce := txvm.NonceTuple(atomicGuaranteeSeed[:], contractSeed[:], bcid, int64(bc.Millis(time.Now().Add(5*time.Minute))))
	hash := txvm.NonceHash(nonce)
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
			// TODO(debnil): Add zero hex string.
			tup.PushdataBytes(hash[:])
		})
	})
}
