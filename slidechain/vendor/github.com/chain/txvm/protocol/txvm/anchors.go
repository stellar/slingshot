package txvm

var zeroAssetID = make([]byte, 32)

func opNonce(vm *VM) {
	exp := vm.popInt()
	blockid := vm.popBytes()

	nonce := vm.logNonce(blockid, int64(exp))
	vm.logTimeRange(0, exp)

	anchor := NonceHash(nonce)
	a := vm.createValue(0, zeroAssetID, anchor[:])

	vm.push(a)
}

func opAnchor(vm *VM) {
	v := vm.peekValue()
	vm.chargeCopy(Bytes(v.anchor))
	vm.push(Bytes(v.anchor))
}

// NonceTuple computes a nonce tuple suitable for logging (with
// vm.log(nonce...)) or hashing (with NonceHash).
func NonceTuple(callerSeed, selfSeed, blockID []byte, expTimeMS int64) Tuple {
	return Tuple{Bytes{NonceCode}, Bytes(callerSeed), Bytes(selfSeed), Bytes(blockID), Int(expTimeMS)}
}

// NonceHash computes the hash of a nonce tuple.
func NonceHash(nonce Tuple) [32]byte {
	return VMHash("Nonce", Encode(nonce))
}
