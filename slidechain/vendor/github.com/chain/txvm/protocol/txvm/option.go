package txvm

import (
	"errors"
	"fmt"
	"io"

	"github.com/chain/txvm/protocol/txvm/op"
)

// Option is the type of a function that can be passed as an option to
// Validate.
type Option struct {
	apply func(vm *VM)
}

// OnLog can be passed as an option to Validate. It adds a callback to
// be invoked when data is added to the transaction log.
func OnLog(h ...func(*VM)) Option {
	return Option{
		apply: func(vm *VM) { vm.onLog = append(vm.onLog, h...) },
	}
}

// OnFinalize can be passed as an option to Validate. It adds a
// callback to be invoked when "finalize" is executed.
func OnFinalize(h ...func(*VM)) Option {
	return Option{
		apply: func(vm *VM) { vm.onFinalize = append(vm.onFinalize, h...) },
	}
}

// BeforeStep can be passed as an option to Validate. It adds a
// callback to be invoked just before each instruction is executed.
func BeforeStep(h ...func(*VM)) Option {
	return Option{
		apply: func(vm *VM) { vm.beforeStep = append(vm.beforeStep, h...) },
	}
}

// AfterStep can be passed as an option to Validate. It adds a
// callback to be invoked after each instruction is executed.
func AfterStep(h ...func(*VM)) Option {
	return Option{
		apply: func(vm *VM) { vm.afterStep = append(vm.afterStep, h...) },
	}
}

// StopAfterFinalize can be passed as an option to Validate. It causes
// execution to terminate after a "finalize" instruction, without
// causing an ErrResidue error if the stacks are non-empty. It is
// useful for computing the transaction ID of a yet-unsigned
// transaction.
var StopAfterFinalize = Option{
	apply: func(vm *VM) {
		vm.stopAfterFinalize = true
	},
}

// EnableExtension can be passed as an option to Validate. It sets
// the extension flag of the VM to true, enabling the ext opcode to
// be called and extensions to be called.
var EnableExtension = Option{
	apply: func(vm *VM) { vm.extension = true },
}

// GetRunlimit causes the vm to write its ending runlimit to the given
// pointer on exit.
func GetRunlimit(runlimit *int64) Option {
	return Option{
		apply: func(vm *VM) {
			vm.onExit = append(vm.onExit, func(vm *VM) {
				*runlimit = vm.runlimit
			})
		},
	}
}

// Resumer can be passed as an option to Validate. It acts like
// StopAfterFinalize, but additionally writes a function to the
// given pointer that can be used to pick up execution after the
// finalize step. This function can be called only once, since
// calling it will affect the VM state.
func Resumer(f *func(rest []byte) error) Option {
	var called bool
	return Option{
		apply: func(vm *VM) {
			vm.stopAfterFinalize = true
			*f = func(rest []byte) (err error) {
				if called {
					return errors.New("resumer function called twice")
				}
				called = true

				defer vm.recoverError(&err)
				vm.stopAfterFinalize = false
				vm.exec(rest)
				if !vm.contract.stack.isEmpty() || !vm.argstack.isEmpty() {
					return vm.wraperr(ErrResidue)
				}
				vm.runHooks(vm.onExit)
				return nil
			}
		},
	}
}

// Trace can be passed as an option to Validate. It causes a textual
// execution trace to be written to the given io.Writer.
func Trace(w io.Writer) Option {
	return Option{
		apply: func(vm *VM) {
			var loglen int
			lastRunstack := len(vm.runstack)
			vm.beforeStep = append(vm.beforeStep, func(vm *VM) {
				if len(vm.runstack) > lastRunstack {
					fmt.Fprintf(w, "=> vm %d\n", len(vm.runstack))
					lastRunstack = len(vm.runstack)
				}
				var name string
				switch {
				case op.IsSmallIntOp(vm.opcode):
					name = fmt.Sprintf("%d", vm.opcode-op.MinSmallInt)
				case op.IsPushdataOp(vm.opcode):
					name = fmt.Sprintf("pushdata%d", len(vm.data))
				default:
					name = op.Name(vm.opcode)
				}
				fmt.Fprintf(w, "vm %d pc %d limit %d ", len(vm.runstack), vm.run.pc, vm.runlimit)
				if vm.contract != nil {
					fmt.Fprintf(w, "contract %x ", vm.contract.seed)
				}
				fmt.Fprintf(w, "%s (%02x)", name, vm.opcode)
				if op.IsPushdataOp(vm.opcode) {
					fmt.Fprintf(w, " %s", Bytes(vm.data))
				}
				fmt.Fprint(w, "\n")
				loglen = len(vm.Log)
			})
			vm.afterStep = append(vm.afterStep, func(vm *VM) {
				if vm.contract.stack.Len() > 0 {
					fmt.Fprint(w, "  con stack:\n")
					for i := 0; i < len(vm.contract.stack); i++ {
						fmt.Fprintf(w, "    %d: %s\n", i, vm.contract.stack[len(vm.contract.stack)-1-i])
					}
				}
				if len(vm.argstack) > 0 {
					fmt.Fprint(w, "  arg stack:\n")
					for i := 0; i < len(vm.argstack); i++ {
						fmt.Fprintf(w, "    %d: %s\n", i, vm.argstack[len(vm.argstack)-1-i])
					}
				}
				if len(vm.Log) > loglen {
					fmt.Fprintf(w, "  log:\n")
					for i := 0; i < len(vm.Log); i++ {
						fmt.Fprintf(w, "    %d: %s\n", i, vm.Log[i])
					}
				}
				if len(vm.runstack) < lastRunstack {
					fmt.Fprintf(w, "<= vm %d\n", lastRunstack)
					lastRunstack = len(vm.runstack)
				}
			})
		},
	}
}
