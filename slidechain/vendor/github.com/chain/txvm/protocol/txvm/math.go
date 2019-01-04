package txvm

import (
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/math/checked"
	"github.com/chain/txvm/protocol/txvm/op"
)

func opAdd(vm *VM) {
	binOp(vm, checked.AddInt64)
}

func opNeg(vm *VM) {
	a := int64(vm.popInt())
	res, ok := checked.NegateInt64(a)
	if !ok {
		panic(errors.Wrap(ErrIntOverflow, "neg"))
	}
	vm.push(Int(res))
}

func opMul(vm *VM) { binOp(vm, checked.MulInt64) }
func opDiv(vm *VM) { binOp(vm, checked.DivInt64) }
func opMod(vm *VM) { binOp(vm, checked.ModInt64) }

func binOp(vm *VM, f func(a, b int64) (int64, bool)) {
	b := int64(vm.popInt())
	a := int64(vm.popInt())
	res, ok := f(a, b)
	if !ok {
		panic(errors.Wrap(ErrIntOverflow, op.Name(vm.opcode)))
	}
	vm.push(Int(res))
}

func opGT(vm *VM) {
	b := vm.popInt()
	a := vm.popInt()
	vm.pushBool(a > b)
}
