package txvm

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/chain/txvm/errors"
)

// ErrInt is returned when int is called on a byte string
// that is not a valid encoding of a varint.
var ErrInt = errorf("invalid varint")

func opDup(vm *VM) {
	item, ok := vm.peek().(Data)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Data"))
	}
	vm.chargeCopy(item)
	vm.push(item)
}

func opDrop(vm *VM) {
	item := vm.pop()
	if !item.isDroppable() {
		panic(errors.WithData(ErrType, "want", "Data, zero Value", "got", fmt.Sprintf("%T", item)))
	}
}

func opEq(vm *VM) {
	v1 := vm.popData()
	v2 := vm.popData()

	res := false

	switch vv1 := v1.(type) {
	case Int:
		if vv2, ok := v2.(Int); ok {
			res = vv1 == vv2
		}
	case Bytes:
		if vv2, ok := v2.(Bytes); ok {
			res = bytes.Equal(vv1, vv2)
		}
	}

	vm.pushBool(res)
}

func opLen(vm *VM) {
	d := vm.popData()
	switch d := d.(type) {
	case Bytes:
		vm.push(Int(len(d)))
	case Tuple:
		vm.push(Int(len(d)))
	default:
		panic(errors.WithData(ErrType, "want", "Bytes, Tuple", "got", fmt.Sprintf("%T", d)))
	}
}

func opTuple(vm *VM) {
	n := int64(vm.popInt())
	if n > int64(vm.contract.stack.Len()) || n < 0 {
		panic(errors.Wrapf(errors.WithData(ErrUnderflow, "len(stack)", vm.contract.stack.Len()), "tuple %d", n))
	}
	vals := make(Tuple, n)
	for n > 0 {
		n--
		v := vm.popData()
		vals[n] = v
	}
	vm.chargeCreate(vals)
	vm.push(vals)
}

func opUntuple(vm *VM) {
	t := vm.popTuple()
	for _, v := range t {
		vm.push(v)
	}
	vm.push(Int(len(t)))
	vm.charge(int64(len(t)))
}

func opField(vm *VM) {
	n := int64(vm.popInt())
	t := vm.popTuple()
	if n < 0 || n >= int64(len(t)) {
		panic(errors.Wrapf(errors.WithData(ErrRange, "len(tuple)", len(t)), "field %d", n))
	}
	vm.chargeCopy(t[n])
	vm.push(t[n])
}

func opEncode(vm *VM) {
	item := vm.popData()
	s := Bytes(Encode(item))
	vm.chargeCreate(s)
	vm.push(s)
}

func opInt(vm *VM) {
	a := vm.popBytes()
	res, n := binary.Uvarint(a)
	if n <= 0 {
		panic(errors.WithData(ErrInt, "int", a))
	}
	// Note: if res > math.MaxInt64, this will convert it to a negative
	// number. This is intentional!
	vm.push(Int(res))
}
