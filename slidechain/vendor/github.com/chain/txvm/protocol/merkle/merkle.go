// Package merkle implements merkle binary trees.
package merkle

import (
	"errors"
	"math"

	"github.com/chain/txvm/crypto/sha3"
	"github.com/chain/txvm/crypto/sha3pool"
)

var (
	leafPrefix      = []byte{0x00}
	interiorPrefix  = []byte{0x01}
	emptyStringHash = sha3.Sum256(nil)
)

// AuditHash stores the hash value and denotes which side of the concatenation
// operation it should be on.
// For example, if we have a hashed item A and an audit hash {Val: B, RightOperator: false},
// the validation is: H(B + A).
type AuditHash struct {
	Val           [32]byte
	RightOperator bool // FALSE indicates the hash should be on the LEFT side of concatenation, TRUE for right side.
}

// Proof returns the proofs required to validate an item at index i, not including the original item i.
// This errors when the requested index is out of bounds.
func Proof(items [][]byte, i int) ([]AuditHash, error) {
	if i < 0 || i >= len(items) {
		return nil, errors.New("index %v is out of bounds")
	}
	if len(items) == 1 {
		return []AuditHash{}, nil
	}

	k := prevPowerOfTwo(len(items))
	recurse := items[:k]
	aggregate := items[k:]
	rightOperator := true
	if i >= k {
		i = i - k
		recurse, aggregate = aggregate, recurse
		rightOperator = false
	}
	res, err := Proof(recurse, i)
	if err != nil {
		return nil, err
	}
	res = append(res, AuditHash{Root(aggregate), rightOperator})
	return res, nil
}

// Root creates a merkle tree from a slice of byte slices
// and returns the root hash of the tree.
func Root(items [][]byte) [32]byte {
	switch len(items) {
	case 0:
		return emptyStringHash

	case 1:
		h := sha3pool.Get256()
		defer sha3pool.Put256(h)

		h.Write(leafPrefix)
		h.Write(items[0])
		var root [32]byte
		h.Read(root[:])
		return root

	default:
		k := prevPowerOfTwo(len(items))
		left := Root(items[:k])
		right := Root(items[k:])

		h := sha3pool.Get256()
		defer sha3pool.Put256(h)
		h.Write(interiorPrefix)
		h.Write(left[:])
		h.Write(right[:])

		var root [32]byte
		h.Read(root[:])
		return root
	}
}

// prevPowerOfTwo returns the largest power of two that is smaller than a given number.
// In other words, for some input n, the prevPowerOfTwo k is a power of two such that
// k < n <= 2k. This is a helper function used during the calculation of a merkle tree.
func prevPowerOfTwo(n int) int {
	// If the number is a power of two, divide it by 2 and return.
	if n&(n-1) == 0 {
		return n / 2
	}

	// Otherwise, find the previous PoT.
	exponent := uint(math.Log2(float64(n)))
	return 1 << exponent // 2^exponent
}
