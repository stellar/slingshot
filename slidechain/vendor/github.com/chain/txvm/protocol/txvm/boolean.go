package txvm

func opNot(vm *VM) {
	b := vm.popBool()
	vm.pushBool(!b)
}

func opAnd(vm *VM) {
	q := vm.popBool()
	p := vm.popBool()
	vm.pushBool(p && q)
}

func opOr(vm *VM) {
	q := vm.popBool()
	p := vm.popBool()
	vm.pushBool(p || q)
}
