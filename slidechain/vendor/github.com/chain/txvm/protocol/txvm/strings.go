package txvm

import "github.com/chain/txvm/errors"

// ErrSliceRange is returned when slice is called with
// a range that is invalid.
var ErrSliceRange = errorf("bad slice range")

func opCat(vm *VM) {
	b := vm.popBytes()
	a := vm.popBytes()
	c := make(Bytes, 0, len(a)+len(b))
	c = append(append(c, a...), b...)
	vm.chargeCreate(c)
	vm.push(c)
}

func opSlice(vm *VM) {
	end := int64(vm.popInt())
	start := int64(vm.popInt())
	str := vm.popBytes()
	if start < 0 || end < start || end > int64(len(str)) {
		panic(errors.WithData(ErrSliceRange, "start", start, "end", end, "len(bytes)", len(str)))
	}
	str2 := append(Bytes{}, str[start:end]...)
	vm.chargeCreate(str2)
	vm.push(str2)
}
