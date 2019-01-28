/*
Package state defines Snapshot, a data structure for holding a
blockchain's state.
*/
package state

import (
	"encoding/binary"
	"fmt"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/patricia"
)

// Snapshot contains a blockchain's state.
//
// TODO: consider making type Snapshot truly immutable.  We already
// handle it that way in many places (with explicit calls to Copy to
// get the right behavior).  PruneNonces and the Apply functions would
// have to produce new Snapshots rather than updating Snapshots in
// place.
type Snapshot struct {
	ContractsTree *patricia.Tree
	NonceTree     *patricia.Tree

	Header         *bc.BlockHeader
	InitialBlockID bc.Hash
	RefIDs         []bc.Hash
}

// PruneNonces modifies a Snapshot, removing all nonce IDs with
// expiration times earlier than the provided timestamp.
func (s *Snapshot) PruneNonces(timestampMS uint64) {
	newTree := new(patricia.Tree)
	*newTree = *s.NonceTree

	patricia.Walk(s.NonceTree, func(item []byte) error {
		_, t := idTime(item)
		if timestampMS > t {
			newTree.Delete(item)
		}
		return nil
	})

	s.NonceTree = newTree
}

// Copy makes a copy of provided snapshot. Copying a snapshot is an
// O(n) operation where n is the number of nonces in the snapshot's
// nonce set.
func Copy(original *Snapshot) *Snapshot {
	c := &Snapshot{
		ContractsTree:  new(patricia.Tree),
		NonceTree:      new(patricia.Tree),
		InitialBlockID: original.InitialBlockID,
		RefIDs:         append([]bc.Hash{}, original.RefIDs...),
	}
	*c.ContractsTree = *original.ContractsTree
	*c.NonceTree = *original.NonceTree
	if original.Header != nil {
		c.Header = new(bc.BlockHeader)
		*c.Header = *original.Header
	}
	return c
}

// Empty returns an empty state snapshot.
func Empty() *Snapshot {
	return &Snapshot{
		ContractsTree: new(patricia.Tree),
		NonceTree:     new(patricia.Tree),
	}
}

// ApplyBlock updates s in place. It runs in three phases:
// PruneNonces, ApplyBlockHeader, and ApplyTx
// (the latter called in a loop for each transaction). Callers
// are free to invoke those phases separately.
func (s *Snapshot) ApplyBlock(block *bc.UnsignedBlock) error {
	s.PruneNonces(block.TimestampMs)

	err := s.ApplyBlockHeader(block.BlockHeader)
	if err != nil {
		return errors.Wrap(err, "applying block header")
	}

	for i, tx := range block.Transactions {
		err = s.ApplyTx(bc.NewCommitmentsTx(tx))
		if err != nil {
			return errors.Wrapf(err, "applying block transaction %d", i)
		}
	}

	return nil
}

// ApplyBlockHeader is the header-specific phase of applying a block
// to the blockchain state. (See ApplyBlock.)
func (s *Snapshot) ApplyBlockHeader(bh *bc.BlockHeader) error {
	bHash := bh.Hash()

	if s.InitialBlockID.IsZero() {
		if bh.Height != 1 {
			return fmt.Errorf("cannot apply block with height %d to an empty state", bh.Height)
		}
		s.InitialBlockID = bHash
	} else if bh.Height == 1 {
		return fmt.Errorf("cannot apply block with height = 1 to an initialized state")
	}

	s.Header = bh
	s.RefIDs = append(s.RefIDs, bHash)

	return nil
}

var (
	// ErrUnfinalized means a transaction with no finalize instruction is being applied to a snapshot.
	ErrUnfinalized = errors.New("unfinalized transaction")

	// ErrEmptyState means ApplyTx was called on an uninitialized blockchain state.
	ErrEmptyState = errors.New("empty state")

	// ErrConflictingNonce means ApplyTx encountered a transaction with a nonce already in the blockchain state.
	ErrConflictingNonce = errors.New("conflicting nonce")

	// ErrNonceReference means a nonce referenced a non-recent, non-initial block ID.
	ErrNonceReference = errors.New("nonce must refer to the initial block, a recent block, or have a zero block ID")

	// ErrPrevout means a transaction tried to input a contract with an unknown ID.
	ErrPrevout = errors.New("invalid prevout")
)

// ApplyTx updates s in place.
func (s *Snapshot) ApplyTx(p *bc.CommitmentsTx) error {
	if s.InitialBlockID.IsZero() {
		return ErrEmptyState
	}

	if !p.Tx.Finalized {
		return ErrUnfinalized
	}

	nonceTree := new(patricia.Tree)
	*nonceTree = *s.NonceTree

	for _, n := range p.Tx.Nonces {
		// Add new nonces. They must not conflict with nonces already
		// present.
		nc, _ := p.NonceCommitments[n.ID]
		if nonceTree.Contains(nc) {
			return errors.Wrapf(ErrConflictingNonce, "nonce %x", n.ID.Bytes())
		}

		if n.BlockID.IsZero() || n.BlockID == s.InitialBlockID {
			// ok
		} else {
			var found bool
			for _, id := range s.RefIDs {
				if id == n.BlockID {
					found = true
					break
				}
			}
			if !found {
				return ErrNonceReference
			}
		}
		nonceTree.Insert(nc)
	}

	conTree := new(patricia.Tree)
	*conTree = *s.ContractsTree

	// Add or remove contracts, depending on if it is an input or output
	for _, con := range p.Tx.Contracts {
		switch con.Type {
		case bc.InputType:
			if !conTree.Contains(con.ID.Bytes()) {
				return errors.Wrapf(ErrPrevout, "ID %x", con.ID.Bytes())
			}
			conTree.Delete(con.ID.Bytes())

		case bc.OutputType:
			err := conTree.Insert(con.ID.Bytes())
			if err != nil {
				return errors.Wrapf(err, "inserting output %x", con.ID.Bytes())
			}
		}
	}

	s.NonceTree = nonceTree
	s.ContractsTree = conTree

	return nil
}

// Height returns the height from the stored latest header.
func (s *Snapshot) Height() uint64 {
	if s == nil || s.Header == nil {
		return 0
	}
	return s.Header.Height
}

// TimestampMS returns the timestamp from the stored latest header.
func (s *Snapshot) TimestampMS() uint64 {
	if s == nil || s.Header == nil {
		return 0
	}
	return s.Header.TimestampMs
}

func idTime(b []byte) (bc.Hash, uint64) {
	h := bc.HashFromBytes(b[:32])
	t := binary.LittleEndian.Uint64(b[32:])
	return h, t
}
