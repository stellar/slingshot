package txvm

import (
	"bytes"
	"fmt"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/math/checked"
)

var (
	// ErrNegAmount is returned when issue or split is called
	// with a negative amount.
	ErrNegAmount = errorf("cannot create negative amounts")

	// ErrSplit is returned when split is called with an amount
	// greater than contained in the value.
	ErrSplit = errorf("not enough value to split")

	// ErrMergeAsset is returned when merge is called with values
	// that have two different assets.
	ErrMergeAsset = errorf("cannot merge different assets")

	// ErrAnchorVal is returned when a non-zero amount value
	// is used for an op that requires an anchor.
	ErrAnchorVal = errorf("value is non-zero and cannot be used as anchor")
)

func opIssue(vm *VM) {
	tag := vm.popBytes()
	amount := vm.popInt()
	if amount < 0 {
		panic(errors.Wrap(errors.WithData(ErrNegAmount, "amount", amount), "issue"))
	}
	anchor := vm.popZeroValue().anchor

	assetID := AssetID(vm.contract.seed, tag)

	val := vm.createValue(int64(amount), assetID[:], anchor)
	vm.push(val)

	vm.logIssuance(int64(amount), assetID[:], anchor)
}

// AssetID produces the ID for the asset whose issuing contract has
// the given ID, and that has the given optional asset tag.
func AssetID(contractSeed, tag []byte) [32]byte {
	h := VMHash("AssetID", append(contractSeed, tag...))
	return h
}

func (vm *VM) peekValue() *value {
	item := vm.peek()
	v, ok := item.(*value)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Value", "got", fmt.Sprintf("%T", item)))
	}
	return v
}

func opAmount(vm *VM) {
	val := vm.peekValue()
	// no cost to copy integers
	vm.push(Int(val.amount))
}

func opAssetID(vm *VM) {
	val := vm.peekValue()
	vm.chargeCopy(Bytes(val.assetID))
	vm.push(Bytes(val.assetID))
}

func opSplit(vm *VM) {
	amount := vm.popInt()
	if amount < 0 {
		panic(errors.Wrap(errors.WithData(ErrNegAmount, "amount", amount), "split"))
	}

	a := vm.popValue()
	if int64(amount) > a.amount {
		panic(errors.WithData(ErrSplit, "a.amount", a.amount, "b.amount", amount))
	}

	anchor1 := VMHash("Split1", a.anchor[:])
	b := vm.createValue(a.amount-int64(amount), a.assetID, anchor1[:])

	anchor2 := VMHash("Split2", a.anchor[:])
	c := vm.createValue(int64(amount), a.assetID, anchor2[:])

	vm.push(b)
	vm.push(c)
}

func opMerge(vm *VM) {
	a := vm.popValue()
	b := vm.popValue()

	if !bytes.Equal(a.assetID, b.assetID) {
		panic(errors.WithData(ErrMergeAsset, "a.asset", a.assetID, "b.asset", b.assetID))
	}

	anchor := VMHash("Merge", append(a.anchor, b.anchor...))
	sum, ok := checked.AddInt64(a.amount, b.amount)
	if !ok {
		panic(errors.Wrap(errors.WithData(ErrIntOverflow, "a.amount", a.amount, "b.amount", b.amount), "merge"))
	}
	val := vm.createValue(sum, a.assetID, anchor[:])
	vm.push(val)
}

func opRetire(vm *VM) {
	val := vm.popValue()
	vm.logRetirement(val.amount, val.assetID, val.anchor)
}

func (vm *VM) popValue() *value {
	item := vm.pop()
	v, ok := item.(*value)
	if !ok {
		panic(errors.WithData(ErrType, "want", "Value", "got", fmt.Sprintf("%T", item)))
	}
	return v
}

func (vm *VM) popZeroValue() *value {
	v := vm.popValue()
	if !v.isZero() {
		panic(errors.WithData(ErrAnchorVal, "asset", v.assetID, "amount", v.amount))
	}
	return v
}
