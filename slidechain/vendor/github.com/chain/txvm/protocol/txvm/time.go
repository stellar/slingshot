package txvm

func opTimeRange(vm *VM) {
	max := vm.popInt()
	min := vm.popInt()
	vm.logTimeRange(min, max)
}
