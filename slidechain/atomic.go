package slidechain

import (
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/op"
	"github.com/chain/txvm/protocol/txvm/txvmutil"
)

const atomicGuaranteeSrc = `
                                             #  con stack       arg stack       log
                                             #  ---------       ---------       ---
                                             #                  zeroval, recip
        get get [drop drop] output           #  recip, zeroval                  {"O", vm.caller, outputid}
`

const zeroSeed [32]byte = make([]byte, 32, 32)

var (
	atomicGuaranteeProg = mustAssemble(atomicGuaranteeSrc)
	atomicGuaranteeSeed = txvm.ContractSeed(atomicGuaranteeProg)
)

// AtomicNonceHash generates a nonce hash for the atomicity-guarantee contract.
func AtomicNonceHash(bcid []byte, expMS int64) [32]byte {
	nonce := txvm.NonceTuple(zeroSeed[:], zeroSeed[:], bcid, expMS)
	return txvm.NonceHash(nonce)
}

// inputAtomicGuarantee writes txvm bytecode to b, calling the atomicity-guarantee contract
// to confirm that the desired recipient pubkey is present.
func inputAtomicGuarantee(b *txvmutil.Builder, pubkey ed25519.PublicKey, bcid []byte, expMS int64) {
	atomicGuaranteeSnapshot(b, pubkey, bcid, expMS)
	b.Op(op.Input).Op(op.Call)
}

// atomicGuaranteeSnapshot adds to b the snapshot of an atomicity-guarantee contract as it appears in the UTXO set.
func atomicGuaranteeSnapshot(b *txvmutil.Builder, pubkey ed25519.PublicKey, bcid []byte, expMS int64) {
	nonceHash := AtomicNonceHash(bcid, expMS)
	b.Tuple(func(contract *txvmutil.TupleBuilder) {
		contract.PushdataByte(txvm.ContractCode)       // 'C'
		contract.PushdataBytes(atomicGuaranteeSeed[:]) // <atomic guarantee seed>
		contract.PushdataBytes(atomicGuaranteeProg)    // [<atomicity guarantee prog>]
		contract.PushdataBytes(pubkey)                 // pubkey
		contract.Tuple(func(tup *txvmutil.TupleBuilder) {
			tup.PushdataByte(txvm.ValueCode)
			tup.PushdataInt64(0)
			tup.PushdataBytes(zeroSeed[:])
			tup.PushdataBytes(nonceHash[:])
		})
	})
}
