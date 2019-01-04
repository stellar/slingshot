package txvm

// TODO(bobg): Update the hook mechanism.

func (vm *VM) runHooks(hooks []func(*VM)) {
	for _, h := range hooks {
		vm.runHook(h)
	}
}

func (vm *VM) runHook(h func(*VM)) {
	defer func() {
		// silently ignore panics
		// TODO(bobg): preserve these errors on the VM object and expose
		// them to the caller
		recover()
	}()

	h(vm)
}
