package txvm

import (
	"crypto/sha256"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/crypto/sha3"
	"github.com/chain/txvm/errors"
)

var (
	// ErrSigSize is returned when checksig is called with a
	// signature length that is invalid for the scheme.
	ErrSigSize = errorf("bad signature length")

	// ErrPubSize is returned when checksig is called with a
	// public key length that is invalid for the scheme.
	ErrPubSize = errorf("bad public key length")

	// ErrSignature is returned when checksig is called with a
	// non-empty signature that fails the check.
	ErrSignature = errorf("invalid non-empty signature")
)

func opVMHash(vm *VM) {
	f := vm.popBytes()
	x := vm.popBytes()
	h := VMHash(string(f), x)
	vm.chargeCreate(Bytes(h[:]))
	vm.push(Bytes(h[:]))
}

func opSHA256(vm *VM) {
	a := vm.popBytes()
	hasher := sha256.New()
	hasher.Write(a)
	h := Bytes(hasher.Sum(nil))
	vm.chargeCreate(h)
	vm.push(h)
}

func opSHA3(vm *VM) {
	a := vm.popBytes()
	h := sha3.Sum256(a)
	vm.chargeCreate(Bytes(h[:]))
	vm.push(Bytes(h[:]))
}

func opCheckSig(vm *VM) {
	scheme := vm.popData() // for future expansion we allow arbitrary data types here, not just ints
	sig := vm.popBytes()
	pubkey := vm.popBytes()
	msg := vm.popBytes()
	// Only empty signatures can return `false` in order
	// to allow deferred batch verification of signatures.
	// If signature is not empty, it MUST be valid,
	// otherwise the entire VM execution fails.
	if len(sig) == 0 {
		vm.pushBool(false)
		return
	}
	vm.charge(2048)
	// Ed25519 signatures have scheme Int(0).
	if schemeint, ok := scheme.(Int); ok && schemeint == 0 {
		checkEd25519(msg, pubkey, sig)
	} else if !vm.extension {
		panic(errors.Wrapf(ErrExt, "checksig cannot validate unknown signature scheme %s", scheme.String()))
	} // else vm.extension==true, so accept unknown schemes as valid
	vm.pushBool(true)
}

func checkEd25519(msg, pubkey, sig Bytes) {
	if len(sig) != ed25519.SignatureSize {
		panic(errors.WithData(ErrSigSize, "got", len(sig), "want", ed25519.SignatureSize))
	}
	if len(pubkey) != ed25519.PublicKeySize {
		panic(errors.WithData(ErrPubSize, "got", len(pubkey), "want", ed25519.PublicKeySize))
	}
	valid := ed25519.Verify(ed25519.PublicKey(pubkey), msg, sig)
	if !valid {
		panic(errors.WithData(ErrSignature, "signature", []byte(sig), "message", []byte(msg), "public key", []byte(pubkey)))
	}
}

// VMHash computes the hash of the "function" f applied to the byte string x.
func VMHash(f string, x []byte) (hash [32]byte) {
	sha3.CShakeSum128(hash[:], x, nil, []byte("ChainVM."+f))
	return hash
}
