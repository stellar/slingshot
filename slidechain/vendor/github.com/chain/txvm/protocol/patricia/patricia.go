// Package patricia computes the Merkle Patricia Tree Hash of a
// set of bit strings, as described in the Chain Protocol spec.
// See https://chain.com/docs/protocol/specifications/data#merkle-patricia-tree.
// Because a patricia tree (a radix tree with a radix of 2)
// provides efficient incremental updates, so does the Merkle
// Patricia Tree Hash computation, making this structure suitable
// for the blockchain full-state commitment.
//
// Type Tree represents a set, where the elements are bit strings.
// The set must be prefix-free -- no item can be a prefix of
// any other -- enforced by Insert.
// The length of each bit string must also be a multiple of eight,
// because the interface uses []byte to represent an item.
//
// The nodes in the tree form an immutable persistent data
// structure. It is okay to copy a Tree struct,
// which contains the root of the tree, to obtain a new tree
// with the same contents. The time to make such a copy is
// independent of the size of the tree.
package patricia

import (
	"bytes"
	"io"

	"github.com/chain/txvm/crypto/sha3pool"
	"github.com/chain/txvm/errors"
)

var (
	leafPrefix     = []byte{0x00}
	interiorPrefix = []byte{0x01}
)

// Tree implements a patricia tree.
type Tree struct {
	root *node
}

// WalkFunc is the type of the function called for each item
// visited by Walk. If an error is returned, processing stops.
type WalkFunc func(item []byte) error

// Walk walks t calling walkFn for each item.
// If an error is returned by walkFn at any point,
// processing is stopped and the error is returned.
func Walk(t *Tree, walkFn WalkFunc) error {
	if t.root == nil {
		return nil
	}
	return walk(t.root, walkFn)
}

func walk(n *node, walkFn WalkFunc) error {
	if n.isLeaf {
		return walkFn(n.key)
	}

	err := walk(n.children[0], walkFn)
	if err != nil {
		return err
	}

	err = walk(n.children[1], walkFn)
	return err
}

// Contains returns whether t contains item.
func (t *Tree) Contains(item []byte) bool {
	if t.root == nil {
		return false
	}

	n := lookup(t.root, item)

	return n != nil
}

func lookup(n *node, key []byte) *node {
	if bytes.Equal(n.key, key) && n.keybit == 7 {
		if !n.isLeaf {
			return nil
		}
		return n
	}
	if !hasPrefix(key, n.key, n.keybit) {
		return nil
	}

	bit := childIdx(key, len(n.key), n.keybit)
	return lookup(n.children[bit], key)
}

// Insert inserts item into t.
//
// It is an error for item to be a prefix of an element
// in t or to contain an element in t as a prefix.
// If item itself is already in t, Insert does nothing
// (and this is not an error).
func (t *Tree) Insert(item []byte) error {
	var hash [32]byte
	h := sha3pool.Get256()
	h.Write(leafPrefix)
	h.Write(item)
	io.ReadFull(h, hash[:])
	sha3pool.Put256(h)

	if t.root == nil {
		t.root = &node{key: item, keybit: 7, hash: &hash, isLeaf: true}
		return nil
	}

	var err error
	t.root, err = insert(t.root, item, &hash)
	return err
}

func insert(n *node, key []byte, hash *[32]byte) (*node, error) {
	if bytes.Equal(n.key, key) && n.keybit == 7 {
		if !n.isLeaf {
			return n, errors.Wrap(errors.New("key provided is a prefix to other keys"))
		}

		return n, nil
	}

	if hasPrefix(key, n.key, n.keybit) {
		if n.isLeaf {
			return n, errors.Wrap(errors.New("key provided is a prefix to other keys"))
		}

		bit := childIdx(key, len(n.key), n.keybit)

		child := n.children[bit]
		child, err := insert(child, key, hash)
		if err != nil {
			return n, err
		}
		newNode := new(node)
		*newNode = *n
		newNode.children[bit] = child // mutation is ok because newNode hasn't escaped yet
		newNode.hash = nil
		return newNode, nil
	}

	if hasPrefix(n.key, key, 7) {
		return n, errors.Wrap(errors.New("key provided is a prefix to other keys"))
	}

	common, bit := commonPrefix(n.key, key)
	newNode := &node{
		key:    key[:common],
		keybit: bit,
	}
	childBit := childIdx(key, common, bit)
	newNode.children[childBit] = &node{
		key:    key,
		keybit: 7,
		hash:   hash,
		isLeaf: true,
	}
	newNode.children[1-childBit] = n
	return newNode, nil
}

// Delete removes item from t, if present.
func (t *Tree) Delete(item []byte) {
	if t.root != nil {
		t.root = delete(t.root, item)
	}
}

func delete(n *node, key []byte) *node {
	if bytes.Equal(key, n.key) && n.keybit == 7 {
		if !n.isLeaf {
			return n
		}
		return nil
	}

	if !hasPrefix(key, n.key, n.keybit) {
		return n
	}

	bit := childIdx(key, len(n.key), n.keybit)
	newChild := delete(n.children[bit], key)

	if newChild == nil {
		return n.children[1-bit]
	}

	if newChild == n.children[bit] {
		return n
	}

	newNode := new(node)
	*newNode = *n
	newNode.key = newChild.key[:len(n.key)] // only use slices of leaf node keys
	newNode.children[bit] = newChild
	newNode.hash = nil

	return newNode
}

// RootHash returns the Merkle root of the tree.
func (t *Tree) RootHash() [32]byte {
	root := t.root
	if root == nil {
		return [32]byte{}
	}
	return root.Hash()
}

func commonPrefix(a, b []byte) (int, byte) {
	var (
		common int
		bit    byte = 7
	)
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			var commonBits byte
			for j := byte(0); j < 8; j++ {
				if mask(a[i], j) != mask(b[i], j) {
					break
				}
				commonBits++
			}
			if commonBits > 0 {
				common++
				bit = commonBits - 1
			}
			break
		}
		common++
	}
	return common, bit
}

func hasPrefix(s, prefix []byte, bit byte) bool {
	if len(prefix) == 0 {
		return true
	}

	if len(prefix) > len(s) {
		return false
	}

	if !bytes.Equal(s[:len(prefix)-1], prefix[:len(prefix)-1]) {
		return false
	}

	return mask(s[len(prefix)-1], bit) == mask(prefix[len(prefix)-1], bit)
}

func mask(b, bits byte) byte {
	return b >> (7 - bits) << (7 - bits)
}

func bitAt(b, bit byte) byte {
	return b >> (7 - bit) & 1
}

func childIdx(key []byte, len int, bit byte) byte {
	if bit == 7 {
		len += 1
		bit = 0
	} else {
		bit++
	}
	return bitAt(key[len-1], bit)
}

// node is a leaf or branch node in a tree
type node struct {
	key      []byte
	keybit   byte
	hash     *[32]byte
	isLeaf   bool
	children [2]*node
}

// Hash will return the hash for this node.
func (n *node) Hash() [32]byte {
	n.calcHash()
	return *n.hash
}

func (n *node) calcHash() {
	if n.hash != nil {
		return
	}

	h := sha3pool.Get256()
	h.Write(interiorPrefix)
	for _, c := range n.children {
		c.calcHash()
		h.Write(c.hash[:])
	}

	var hash [32]byte
	io.ReadFull(h, hash[:])
	n.hash = &hash
	sha3pool.Put256(h)
}
