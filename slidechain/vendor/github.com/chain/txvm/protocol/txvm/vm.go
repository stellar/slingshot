package txvm

import (
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/math/checked"
	"github.com/chain/txvm/protocol/txvm/op"
)

//go:generate go run gen.go

// A "run" is a program and a position in it
type run struct {
	pc   int64
	prog []byte
}

// VM is a virtual machine for executing Chain Protocol transactions.
type VM struct {
	// Config/setup fields
	txVersion         int64
	runlimit          int64
	extension         bool
	stopAfterFinalize bool
	onFinalize        []func(*VM)
	onLog             []func(*VM)
	beforeStep        []func(*VM)
	afterStep         []func(*VM)
	onExit            []func(*VM)

	// Runtime fields
	argstack  stack
	run       run // TODO(bobg): move run/runstack into txvmutil.
	runstack  []run
	unwinding bool
	contract  *contract
	caller    []byte
	data      []byte
	opcode    byte

	// Results

	// TxID is the unique id of the transaction. It is only set if
	// Finalized is true.
	TxID [32]byte

	// Log is the record of the transaction's effects.
	Log []Tuple

	// Finalized is true if and only if the finalize instruction was
	// executed.
	Finalized bool
}

var (
	// ErrResidue is produced by Validate when execution leaves the
	// argument stack or current contract stack non-empty.
	ErrResidue = errorf("residue on stack(s)")

	// ErrRunlimit indicates that the available runlimit has been exhausted.
	ErrRunlimit = errorf("runlimit exhausted")

	// ErrVersion means Validate was called with a version less than 3.
	ErrVersion = errorf("transaction version cannot be less than 3")

	// ErrStackRange means an op tried to access a location that was out of
	// range for the stack it was accessing.
	ErrStackRange = errorf("index out of stack range")

	// ErrRange is returned when an op tries to access a location that
	// is out of range for the value it was accessing.
	ErrRange = errorf("index out of range")

	// ErrType is returned when a stack item has a different type
	// than was expected.
	ErrType = errorf("invalid item type")

	// ErrFields is returned when a struct has different fields than
	// was expected. Is returned during an uninspect function call.
	ErrFields = errorf("invalid struct fields")

	// ErrUnderflow is returned when an op pops or peeks an item
	// on the stack and the stack is not deep enough.
	ErrUnderflow = errorf("stack underflow")

	// ErrIntOverflow is returned when any arithmetic exceeds the
	// range of int64.
	ErrIntOverflow = vmError(checked.ErrOverflow)

	// ErrExt is returned when extension operations are performed
	// and the extension flag is false.
	ErrExt = errorf("extension flag is false")

	emptySeed = make([]byte, 32)
)

// Validate is the main entrypoint to txvm. It runs the given program,
// producing its transaction ID if it gets as far as a "finalize"
// instruction. Other runtime information can be inspected via
// callbacks, which are supplied via the Option arguments.
func Validate(prog []byte, txVersion, runlimit int64, o ...Option) (*VM, error) {
	if txVersion < 3 {
		return nil, ErrVersion
	}

	con := &contract{seed: emptySeed, program: prog, typecode: ContractCode}
	vm := &VM{
		txVersion: txVersion,
		runlimit:  runlimit,
		contract:  con,
		caller:    emptySeed,
	}

	for _, o := range o {
		o.apply(vm)
	}

	err := vm.validate(prog)
	vm.runHooks(vm.onExit)
	return vm, err
}

func (vm *VM) validate(txprog []byte) (err error) {
	defer vm.recoverError(&err)

	if int64(len(txprog)) > vm.runlimit {
		return vm.wraperr(ErrRunlimit)
	}

	vm.exec(txprog)

	if !vm.stopAfterFinalize && (!vm.contract.stack.isEmpty() || !vm.argstack.isEmpty()) {
		return vm.wraperr(ErrResidue)
	}
	return nil
}

func (vm *VM) exec(prog []byte) {
	if len(vm.run.prog) > 0 {
		vm.runstack = append(vm.runstack, vm.run)
		defer func() {
			vm.run = vm.runstack[len(vm.runstack)-1]
			vm.runstack = vm.runstack[:len(vm.runstack)-1]
		}()
	}
	vm.run.prog = prog
	vm.run.pc = 0
	for vm.run.pc < int64(len(vm.run.prog)) {
		if vm.unwinding {
			return
		}
		vm.step()
		if vm.Finalized && vm.stopAfterFinalize {
			break
		}
	}
}

func (vm *VM) step() {
	opcode, data, n, err := op.DecodeInst(vm.run.prog[vm.run.pc:])
	if err != nil {
		panic(vmError(err))
	}
	vm.opcode = opcode
	vm.data = data
	vm.runHooks(vm.beforeStep)
	vm.charge(1)
	vm.run.pc += n
	switch {
	case op.IsSmallIntOp(opcode):
		vm.push(Int(opcode - op.MinSmallInt))
	case op.IsPushdataOp(opcode):
		d := Bytes(data)
		vm.chargeCreate(d)
		vm.push(d)
	default:
		f := opFuncs[opcode]
		f(vm)
	}
	vm.runHooks(vm.afterStep)
}

func (vm *VM) charge(n int64) {
	vm.runlimit -= n
	if vm.runlimit < 0 {
		panic(ErrRunlimit)
	}
}

// stack access

func (vm *VM) push(v Item) {
	vm.contract.stack.push(v)
}

func (vm *VM) pushBool(b bool) {
	var n Int
	if b {
		n = 1
	}
	vm.push(n)
}

func (vm *VM) pop() Item {
	res, ok := vm.contract.stack.pop()
	if !ok {
		panic(errors.Wrap(ErrUnderflow, "popping stack item"))
	}
	return res
}

func (vm *VM) popData() Data {
	v, ok := vm.pop().(Data)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Data"))
	}
	return v
}

func (vm *VM) popBool() bool {
	v := vm.popData()
	if n, ok := v.(Int); ok {
		return n != 0
	}
	return true
}

func (vm *VM) popBytes() Bytes {
	v, ok := vm.pop().(Bytes)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Bytes"))
	}
	return v
}

func (vm *VM) popInt() Int {
	v, ok := vm.pop().(Int)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Int"))
	}
	return v
}

func (vm *VM) popTuple() Tuple {
	v, ok := vm.pop().(Tuple)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Tuple"))
	}
	return v
}

func (vm *VM) peek() Item {
	v, ok := vm.contract.stack.peek(0)
	if !ok {
		panic(errors.Wrap(ErrUnderflow, "peeking stack item"))
	}
	return v
}

func (vm *VM) peekNth(n int64) Item {
	v, ok := vm.contract.stack.peek(n)
	if !ok {
		panic(errors.Wrapf(ErrStackRange, "peeking stack item %d", n))
	}
	return v
}

func (vm *VM) chargeCreate(v Item) {
	var (
		cost int64
		ok   = true
	)

	switch val := v.(type) {
	case Entry:
		cost = 128
	case Bytes:
		cost, ok = checked.AddInt64(1, int64(len(val)))
	case Tuple:
		cost, ok = checked.AddInt64(1, int64(len(val)))
	}
	if !ok {
		panic(errors.Wrap(ErrIntOverflow, "charging create cost"))
	}
	vm.charge(cost)
}

func (vm *VM) chargeCopy(v Data) {
	var (
		cost int64
		ok   = true
	)

	switch val := v.(type) {
	case Bytes:
		cost, ok = checked.AddInt64(1, int64(len(val)))
	case Tuple:
		cost, ok = checked.AddInt64(1, int64(len(val)))
	}
	if !ok {
		panic(errors.Wrap(ErrIntOverflow, "charging copy cost"))
	}
	vm.charge(cost)
}

// perr must be non-nil
func (vm *VM) recoverError(perr *error) {
	if r := recover(); r != nil {
		var ok bool
		vmErr, ok := r.(vmError)
		if !ok {
			panic(r)
		} else {
			*perr = vm.wraperr(vmErr)
		}
	}
}
