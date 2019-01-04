package bc

import (
	"bytes"

	"github.com/chain/txvm/protocol/merkle"
)

// TxMerkleRoot creates a merkle tree from a slice of Transactions and
// returns the root hash of the tree.
func TxMerkleRoot(txs []*Tx) Hash {
	var txCommitments [][]byte

	for _, tx := range txs {
		var b bytes.Buffer
		tx.WriteWitnessCommitmentTo(&b)
		txCommitments = append(txCommitments, b.Bytes())
	}

	return NewHash(merkle.Root(txCommitments))
}
