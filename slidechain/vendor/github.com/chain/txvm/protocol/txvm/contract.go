package txvm

import (
	"fmt"

	"github.com/chain/txvm/errors"
)

var (
	// ErrNonEmpty is returned when a contract completes execution
	// with a non-empty stack.
	ErrNonEmpty = errorf("contract ended with non-empty stack")

	// ErrUnportable is returned when a contract calls output or wrap
	// with unportable items on its stack.
	ErrUnportable = errorf("contract contains unportable stack items")

	// ErrPrv is returned when prv is called.
	ErrPrv = errorf("prv called")
)

func (con *contract) snapshot() (encoded, id Bytes) {
	return contractSnapshot(con.inspect())
}

func contractSnapshot(t Tuple) (encoded, id Bytes) {
	encoded = Encode(t)
	h := VMHash("SnapshotID", encoded)
	return encoded, h[:]
}

func opContract(vm *VM) {
	prog := vm.popBytes()
	con := vm.createContract(prog)
	vm.push(con)
}

func opCall(vm *VM) {
	item := vm.pop()
	con, ok := item.(*contract)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Contract, WrappedContract", "got", fmt.Sprintf("%T", item)))
	}

	con.typecode = ContractCode // unwrap on the fly

	prevContract := vm.contract
	prevCaller := vm.caller

	vm.caller = vm.contract.seed
	vm.contract = con

	vm.exec(con.program)

	if !vm.unwinding && len(vm.contract.stack) > 0 {
		panic(errors.Wrapf(ErrNonEmpty, "contract %x", con.seed))
	}

	vm.unwinding = false
	vm.contract = prevContract
	vm.caller = prevCaller
}

func opOutput(vm *VM) {
	if !stackPortable(vm.contract.stack) {
		panic(errors.Wrap(ErrUnportable, "output"))
	}
	prog := vm.popBytes()
	vm.contract.program = prog
	snapshot, snapshotID := vm.contract.snapshot()
	vm.chargeCreate(snapshot)
	vm.logOutput(snapshotID)
	vm.unwinding = true
}

func opInput(vm *VM) {
	t := vm.popTuple()
	_, snapshotID := contractSnapshot(t)

	con := new(contract)
	err := con.uninspect(t)
	if err != nil {
		panic(err)
	}
	vm.chargeCreate(con)
	vm.push(con)

	vm.logInput(snapshotID)
}

func opYield(vm *VM) {
	prog := vm.popBytes()
	vm.contract.program = prog
	vm.argstack.push(vm.contract)
	vm.unwinding = true
}

func opWrap(vm *VM) {
	if !stackPortable(vm.contract.stack) {
		panic(errors.Wrap(ErrUnportable, "wrap"))
	}
	prog := vm.popBytes()
	vm.contract.typecode = WrappedContractCode
	vm.contract.program = prog
	vm.argstack.push(vm.contract)
	vm.unwinding = true
}

func opContractProgram(vm *VM) {
	vm.chargeCopy(Bytes(vm.contract.program))
	vm.push(Bytes(vm.contract.program))
}

func opSelf(vm *VM) {
	vm.chargeCopy(Bytes(vm.contract.seed))
	vm.push(Bytes(vm.contract.seed))
}

func opSeed(vm *VM) {
	item := vm.peek()
	c, ok := item.(*contract)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Contract, WrappedContract", "got", fmt.Sprintf("%T", item)))
	}
	vm.chargeCopy(Bytes(c.seed))
	vm.push(Bytes(c.seed))
}

func opCaller(vm *VM) {
	vm.chargeCopy(Bytes(vm.caller))
	vm.push(Bytes(vm.caller))
}

func opGet(vm *VM) {
	item, ok := vm.argstack.pop()
	if !ok {
		panic(errors.Wrap(ErrUnderflow, "get"))
	}
	vm.push(item)
}

func opPut(vm *VM) {
	item := vm.pop()
	vm.argstack.push(item)
}

func opExt(vm *VM) {
	if !vm.extension {
		panic(errors.Wrap(ErrExt, "ext"))
	}
	_ = vm.popData()
}

func opPrv(vm *VM) {
	panic(ErrPrv)
}

func stackPortable(stack stack) bool {
	for _, item := range stack {
		if !item.isPortable() {
			return false
		}
	}
	return true
}

// ContractSeed computes the seed of a contract whose initial program is
// prog.
func ContractSeed(prog []byte) [32]byte {
	return VMHash("ContractSeed", prog)
}
