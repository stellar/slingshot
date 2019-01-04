package txvm

import (
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/txvm/op"
)

// ErrBitLen is returned when a binary bitwise op is called
// on byte strings of different lengths.
var ErrBitLen = errorf("mismatched byte lengths for binary bitwise op")

func opBitNot(vm *VM) {
	s := vm.popBytes()
	t := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		t[i] = ^s[i]
	}
	vm.chargeCreate(Bytes(t))
	vm.push(Bytes(t))
}

func opBitAnd(vm *VM) { bitOp(vm, and) }
func opBitOr(vm *VM)  { bitOp(vm, or) }
func opBitXor(vm *VM) { bitOp(vm, xor) }

func bitOp(vm *VM, f func(a, b byte) byte) {
	b := vm.popBytes()
	a := vm.popBytes()
	if len(a) != len(b) {
		panic(errors.Wrap(errors.WithData(ErrBitLen, "len(a)", len(a), "len(b)", len(b)), op.Name(vm.opcode)))
	}
	c := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		c[i] = f(a[i], b[i])
	}
	vm.chargeCreate(Bytes(c))
	vm.push(Bytes(c))
}

func and(a, b byte) byte { return a & b }
func or(a, b byte) byte  { return a | b }
func xor(a, b byte) byte { return a ^ b }
