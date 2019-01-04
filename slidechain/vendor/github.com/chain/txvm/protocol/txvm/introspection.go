package txvm

// Version returns the current transaction version.
func (vm *VM) Version() int64 {
	return vm.txVersion
}

// Runlimit returns the current remaining runlimit in the VM.
func (vm *VM) Runlimit() int64 {
	return vm.runlimit
}

// OpCode returns the current opcode in the VM. Use it in BeforeStep
// and AfterStep callbacks to discover the instruction being executed.
func (vm *VM) OpCode() byte {
	return vm.opcode
}

// StackLen returns the length of the stack of the VM's current
// contract.
func (vm *VM) StackLen() int {
	return len(vm.contract.stack)
}

// StackItem returns an "inspected" copy of an item on the VM's
// current contract stack, by position. Position 0 is the bottom of
// the stack and StackLen()-1 is the top.
func (vm *VM) StackItem(i int) Data {
	return vm.contract.stack[i].inspect()
}

// Seed returns the contract seed of the VM's current contract.
func (vm *VM) Seed() []byte {
	return vm.contract.seed
}
