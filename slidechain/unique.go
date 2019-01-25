package slidechain

import "github.com/chain/txvm/protocol/txvm"

var zeroSeed [32]byte

// UniqueNonceHash returns a nonce hash that can be used before pegging
// and after importing to prevent replay attacks.
func UniqueNonceHash(bcid []byte, expMS int64) [32]byte {
	nonce := txvm.NonceTuple(zeroSeed[:], zeroSeed[:], bcid, expMS)
	return txvm.NonceHash(nonce)
}
