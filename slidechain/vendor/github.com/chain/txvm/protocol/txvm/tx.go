package txvm

import (
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/merkle"
)

// ErrUnfinalized is returned when txid is called before finalize.
var ErrUnfinalized = errorf("cannot be called until after finalize")

func opFinalize(vm *VM) {
	anchor := vm.popZeroValue().anchor

	vm.logFinalize(anchor)

	vm.Finalized = true

	items := make([][]byte, 0, len(vm.Log))
	for _, item := range vm.Log {
		items = append(items, Encode(item))
	}

	vm.TxID = merkle.Root(items)
	vm.runHooks(vm.onFinalize)
}

func opTxID(vm *VM) {
	if !vm.Finalized {
		panic(errors.Wrap(ErrUnfinalized, "txid"))
	}
	vm.chargeCopy(Bytes(vm.TxID[:]))
	vm.push(Bytes(vm.TxID[:]))
}
