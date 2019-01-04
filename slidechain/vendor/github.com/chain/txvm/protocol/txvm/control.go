package txvm

import (
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/math/checked"
)

var (
	// ErrVerifyFail is the error produced by a verify that fails.
	ErrVerifyFail = errorf("verify fail")

	// ErrJump is returned when the jump destination for a jumpif
	// is not within the bounds of the program.
	ErrJump = errorf("invalid jump destination")
)

func opVerify(vm *VM) {
	b := vm.popBool()
	if !b {
		panic(ErrVerifyFail)
	}
}

func opJumpIf(vm *VM) {
	offset := int64(vm.popInt())
	cond := vm.popBool()
	if !cond {
		return
	}
	dest, ok := checked.AddInt64(vm.run.pc, offset)
	if !ok {
		panic(errors.Wrap(ErrIntOverflow, "computing jump destination"))
	}
	if dest < 0 || dest > int64(len(vm.run.prog)) {
		panic(errors.WithData(ErrJump, "destination", dest, "len(prog)", len(vm.run.prog)))
	}
	vm.run.pc = dest
}

func opExec(vm *VM) {
	prog := vm.popBytes()
	vm.exec(prog)
}
