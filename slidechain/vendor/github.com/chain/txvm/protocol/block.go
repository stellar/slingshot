package protocol

import (
	"context"
	"encoding/hex"
	"sync/atomic"
	"time"

	"github.com/chain/txvm/crypto/ed25519"
	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/log"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/patricia"
	"github.com/chain/txvm/protocol/state"
)

var (
	// ErrBadContractsRoot is returned when the computed contracts merkle root
	// disagrees with the one declared in a block header.
	ErrBadContractsRoot = errors.New("invalid contracts merkle root")

	// ErrBadNoncesRoot is returned when the computed nonces merkle root
	// disagrees with the one declared in a block header.
	ErrBadNoncesRoot = errors.New("invalid nonces merkle root")
)

// GetBlock returns the block at the given height, if there is one,
// otherwise it returns an error.
func (c *Chain) GetBlock(ctx context.Context, height uint64) (*bc.Block, error) {
	return c.store.GetBlock(ctx, height)
}

// GenerateBlock generates a valid, but unsigned, candidate block from
// the current pending transaction pool. It returns the new block and
// a snapshot of what the state snapshot is if the block is applied.
//
// After generating the block, the pending transaction pool will be
// empty.
func (c *Chain) GenerateBlock(ctx context.Context, timestampMS uint64, txs []*bc.CommitmentsTx) (*bc.UnsignedBlock, *state.Snapshot, error) {
	err := c.bb.Start(c.State(), timestampMS)
	if err != nil {
		return nil, nil, err
	}
	for _, tx := range txs {
		err := c.bb.AddTx(tx)
		if err != nil {
			log.Printkv(ctx, "event", "invalid tx", "error", err, "tx", hex.EncodeToString(tx.Tx.Program))
		}
	}
	return c.bb.Build()
}

// CommitAppliedBlock takes a block, commits it to persistent storage and
// sets c's state. Unlike CommitBlock, it accepts an already applied
// snapshot. CommitAppliedBlock is idempotent.
func (c *Chain) CommitAppliedBlock(ctx context.Context, block *bc.Block, snapshot *state.Snapshot) error {
	err := c.store.SaveBlock(ctx, block)
	if err != nil {
		return errors.Wrap(err, "storing block")
	}
	curState := c.State()

	// CommitAppliedBlock needs to be idempotent. If block's height is less than or
	// equal to c's current block, then it was already applied. Because
	// SaveBlock didn't error with a conflict, we know it's not a different
	// block at the same height.
	if block.Height <= curState.Height() {
		return nil
	}
	return c.finalizeCommitState(ctx, snapshot)
}

// CommitBlock takes a block, commits it to persistent storage and applies
// it to c. CommitBlock is idempotent. A duplicate call with a previously
// committed block will succeed.
func (c *Chain) CommitBlock(ctx context.Context, block *bc.Block) error {
	err := c.store.SaveBlock(ctx, block)
	if err != nil {
		return errors.Wrap(err, "storing block")
	}
	curSnapshot := c.State()

	// CommitBlock needs to be idempotent. If block's height is less than or
	// equal to c's current block, then it was already applied. Because
	// SaveBlock didn't error with a conflict, we know it's not a different
	// block at the same height.
	if block.Height <= curSnapshot.Height() {
		return nil
	}

	snapshot := state.Copy(curSnapshot)
	err = snapshot.ApplyBlock(block.UnsignedBlock)
	if err != nil {
		return err
	}
	if block.ContractsRoot.Byte32() != snapshot.ContractsTree.RootHash() {
		return ErrBadContractsRoot
	}
	if block.NoncesRoot.Byte32() != snapshot.NonceTree.RootHash() {
		return ErrBadNoncesRoot
	}
	return c.finalizeCommitState(ctx, snapshot)
}

func (c *Chain) finalizeCommitState(ctx context.Context, snapshot *state.Snapshot) error {
	// Save the blockchain state tree snapshot to persistent storage
	// if we haven't done it recently.
	lastQueuedHeight := atomic.LoadUint64(&c.lastQueuedSnapshotHeight)
	if lastQueuedHeight+c.blocksPerSnapshot <= snapshot.Height() {
		c.queueSnapshot(ctx, snapshot)
	}
	// setState will update c's current block and snapshot, or no-op
	// if another goroutine has already updated the state.
	c.setState(snapshot)

	// The below FinalizeHeight will notify other cored processes that
	// the a new block has been committed. It may result in a duplicate
	// attempt to update c's height but setState and setHeight safely
	// ignore duplicate heights.
	err := c.store.FinalizeHeight(ctx, snapshot.Height())
	return errors.Wrap(err, "finalizing block")
}

func (c *Chain) queueSnapshot(ctx context.Context, s *state.Snapshot) {
	// Non-blockingly queue the snapshot for storage.
	select {
	case c.pendingSnapshots <- s:
		atomic.StoreUint64(&c.lastQueuedSnapshotHeight, s.Height())
	default:
		// Skip it; saving snapshots is taking longer than the snapshotting period.
		lastQueuedHeight := atomic.LoadUint64(&c.lastQueuedSnapshotHeight)
		log.Printf(ctx, "snapshot storage is taking too long; %d blocks since last snapshot queued",
			s.Height()-lastQueuedHeight)
	}
}

// NewInitialBlock produces the first block for a new blockchain,
// using the given pubkeys and quorum for its NextPredicate.
func NewInitialBlock(pubkeys []ed25519.PublicKey, quorum int, timestamp time.Time) (*bc.Block, error) {
	// TODO(kr): move this into a lower-level package (e.g. chain/protocol/bc)
	// so that other packages (e.g. chain/protocol/validation) unit tests can
	// call this function.
	root := bc.TxMerkleRoot(nil) // calculate the zero value of the tx merkle root
	patRoot := bc.NewHash(new(patricia.Tree).RootHash())

	var pkBytes [][]byte
	for _, pk := range pubkeys {
		pkBytes = append(pkBytes, pk)
	}

	b := &bc.Block{
		UnsignedBlock: &bc.UnsignedBlock{
			BlockHeader: &bc.BlockHeader{
				Version:          3,
				Height:           1,
				TimestampMs:      bc.Millis(timestamp),
				TransactionsRoot: &root,
				ContractsRoot:    &patRoot,
				NoncesRoot:       &patRoot,
				NextPredicate: &bc.Predicate{
					Version: 1,
					Quorum:  int32(quorum),
					Pubkeys: pkBytes,
				},
			},
		},
	}
	return b, nil
}
