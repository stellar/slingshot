package slidechain

import (
	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/protocol/txbuilder/standard"
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

var (
	atomicGuaranteeProg = mustAssemble(atomicGuaranteeSrc)
	atomicGuaranteeSeed = txvm.ContractSeed(atomicGuaranteeProg)
)

// AtomicNonceHash generates a nonce hash for the atomicity-guarantee contract.
func AtomicNonceHash(bcid []byte, exp int64) [32]byte {
	contractSeed := standard.AssetContractSeed[3] // Hardcoded TxVM version ID.
	nonce := txvm.NonceTuple(atomicGuaranteeSeed[:], contractSeed[:], bcid, exp)
	return txvm.NonceHash(nonce)
}

// inputAtomicGuarantee writes txvm bytecode to b, calling the atomicity-guarantee contract
// to confirm that the desired recipient pubkey is present.
func inputAtomicGuarantee(b *txvmutil.Builder, pubkey ed25519.PublicKey, bcid []byte, exp int64) {
	atomicGuaranteeSnapshot(b, pubkey, bcid, exp)
	b.Op(op.Input).Op(op.Call)
}

// atomicGuaranteeSnapshot adds to b the snapshot of an atomicity-guarantee contract as it appears in the UTXO set.
func atomicGuaranteeSnapshot(b *txvmutil.Builder, pubkey ed25519.PublicKey, bcid []byte, exp int64) {
	nonceHash := AtomicNonceHash(bcid, exp)
	b.Tuple(func(contract *txvmutil.TupleBuilder) {
		contract.PushdataByte(txvm.ContractCode)       // 'C'
		contract.PushdataBytes(atomicGuaranteeSeed[:]) // <atomic guarantee seed>
		contract.PushdataBytes(atomicGuaranteeProg)    // [<atomicity guarantee prog>]
		contract.PushdataBytes(pubkey)                 // pubkey
		contract.Tuple(func(tup *txvmutil.TupleBuilder) {
			tup.PushdataByte(txvm.ValueCode)
			tup.PushdataInt64(0)
			tup.PushdataBytes("x'0000000000000000000000000000000000000000000000000000000000000000'")
			tup.PushdataBytes(nonceHash[:])
		})
	})
}
