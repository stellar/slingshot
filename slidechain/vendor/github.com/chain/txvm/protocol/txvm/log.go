package txvm

import "github.com/chain/txvm/errors"

// ErrFinalized is returned when an op that logs an item
// is called after finalize has been called.
var ErrFinalized = errorf("cannot add to tx log after finalize")

func opLog(vm *VM) {
	data := vm.popData()
	vm.log(Bytes{LogCode}, Bytes(vm.contract.seed[:]), data)
}

func opPeekLog(vm *VM) {
	i := int64(vm.popInt())
	if i < 0 || i >= int64(len(vm.Log)) {
		panic(errors.Wrapf(ErrRange, "peeklog %d", i))
	}
	vm.chargeCopy(vm.Log[i])
	vm.push(vm.Log[i])
}

// charges the creation cost of a tuple containing the given data and logs it
func (vm *VM) log(v ...Data) Tuple {
	if vm.Finalized {
		panic(ErrFinalized)
	}
	t := Tuple(v)
	vm.chargeCreate(t)
	vm.Log = append(vm.Log, t)
	vm.runHooks(vm.onLog)
	return t
}

func (vm *VM) logNonce(blockID []byte, exp int64) Tuple {
	return vm.log(NonceTuple(vm.caller, vm.contract.seed, blockID, exp)...)
}

func (vm *VM) logTimeRange(mintime, maxtime Int) {
	vm.log(Bytes{TimerangeCode}, Bytes(vm.contract.seed), mintime, maxtime)
}

func (vm *VM) logOutput(snapshotID []byte) {
	vm.log(Bytes{OutputCode}, Bytes(vm.caller), Bytes(snapshotID))
}

func (vm *VM) logInput(snapshotID []byte) {
	vm.log(Bytes{InputCode}, Bytes(vm.contract.seed), Bytes(snapshotID))
}

func (vm *VM) logFinalize(anchor []byte) {
	vm.log(Bytes{FinalizeCode}, Bytes(vm.contract.seed), Int(vm.txVersion), Bytes(anchor))
}

func (vm *VM) logRetirement(amount int64, assetID, anchor []byte) {
	vm.log(Bytes{RetireCode}, Bytes(vm.contract.seed), Int(amount), Bytes(assetID), Bytes(anchor))
}

func (vm *VM) logIssuance(amount int64, assetID, anchor []byte) {
	vm.log(Bytes{IssueCode}, Bytes(vm.caller), Int(amount), Bytes(assetID), Bytes(anchor))
}
