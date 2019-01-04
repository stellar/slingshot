package txvm

import (
	"fmt"

	"github.com/chain/txvm/errors"
)

// Type codes for inspected entries and for log items.
const (
	InputCode           byte = 'I'
	OutputCode          byte = 'O'
	LogCode             byte = 'L'
	TimerangeCode       byte = 'R'
	NonceCode           byte = 'N'
	IssueCode           byte = 'A'
	RetireCode          byte = 'X'
	FinalizeCode        byte = 'F'
	ValueCode           byte = 'V'
	ContractCode        byte = 'C'
	WrappedContractCode byte = 'W'
)

// Entry is the interface for txvm stack items that are not plain
// data.
type Entry interface {
	Item
	uninspect(Tuple) error
}

type value struct {
	amount  int64
	assetID []byte
	anchor  []byte
}

func (x *value) isPortable() bool  { return true }
func (x *value) isZero() bool      { return x.amount == 0 }
func (x *value) isDroppable() bool { return x.isZero() }

func (x *value) inspect() Tuple {
	return Tuple{
		Bytes{ValueCode},
		Int(x.amount),
		Bytes(x.assetID),
		Bytes(x.anchor),
	}
}

func (x *value) uninspect(t Tuple) error {
	if len(t) != 4 {
		return errors.WithData(ErrFields, "want", "4 fields", "type", "value", "got", len(t))
	}
	typ := extractTypeCode(t)
	if typ != ValueCode {
		return errors.WithData(ErrFields, "want", "typecode V for value", "got", t[0])
	}
	if item, ok := t[1].(Int); ok {
		x.amount = int64(item)
	} else {
		return errors.WithData(ErrFields, "want", "Int for value.amount", "got", t[1])
	}
	if item, ok := t[2].(Bytes); ok {
		x.assetID = []byte(item)
	} else {
		return errors.WithData(ErrFields, "want", "Bytes for value.assetID", "got", t[2])
	}
	if item, ok := t[3].(Bytes); ok {
		x.anchor = []byte(item)
	} else {
		return errors.WithData(ErrFields, "want", "Bytes for value.anchor", "got", t[3])
	}
	return nil
}

func (x *value) String() string {
	return fmt.Sprintf("value{%d, %x, %x}", x.amount, x.assetID, x.anchor)
}

func (vm *VM) createValue(amount int64, assetID, anchor []byte) *value {
	vm.charge(128)
	return &value{
		amount:  amount,
		assetID: assetID,
		anchor:  anchor,
	}
}

type contract struct {
	typecode byte
	seed     []byte
	program  []byte
	stack    stack
}

func (x *contract) isPortable() bool  { return x.typecode == WrappedContractCode }
func (x *contract) isDroppable() bool { return false }

func (x *contract) inspect() Tuple {
	result := Tuple{
		Bytes{x.typecode},
		Bytes(x.seed),
		Bytes(x.program),
	}
	for _, item := range x.stack {
		result = append(result, item.inspect())
	}
	return result
}

func (x *contract) uninspect(t Tuple) error {
	if len(t) < 3 {
		return errors.WithData(ErrFields, "want", "at least 3 fields", "type", "contract", "got", len(t))
	}
	typ := extractTypeCode(t)
	if !(typ == ContractCode || typ == WrappedContractCode) {
		return errors.WithData(ErrFields, "want", "typecode C or W for Contract/WrappedContract", "got", t[0])
	}
	x.typecode = typ
	if item, ok := t[1].(Bytes); ok {
		x.seed = []byte(item)
	} else {
		return errors.WithData(ErrFields, "want", "Bytes for contract.seed", "got", t[1])
	}
	if item, ok := t[2].(Bytes); ok {
		x.program = []byte(item)
	} else {
		return errors.WithData(ErrFields, "want", "Bytes for contract.program", "got", t[2])
	}
	x.stack = stack{}
	for i, item := range t[3:] {
		if subtuple, ok := item.(Tuple); ok {
			y, err := uninspect(subtuple)
			if err != nil {
				return errors.Wrapf(err, "uninspecting stack item %d", len(x.stack))
			}
			x.stack = append(x.stack, y)
		} else {
			return errors.WithData(ErrFields, "want", "subtuple", "got", item, "index", i)
		}
	}
	return nil
}

func (x *contract) String() string {
	prefix := "contract{"
	if x.typecode == WrappedContractCode {
		prefix = "wrappedcontract{"
	}
	return prefix + fmt.Sprintf("%x", x.seed) + ", " + fmt.Sprintf("%x", x.program) + ", " + x.stack.String() + "}"
}

func (vm *VM) createContract(prog []byte) *contract {
	vm.charge(128)
	seed := ContractSeed(prog)
	return &contract{typecode: ContractCode, seed: seed[:], program: prog}
}

func extractTypeCode(t Tuple) byte {
	code, ok := t[0].(Bytes)
	if !ok || len(code) != 1 {
		return 0
	}
	return code[0]
}
