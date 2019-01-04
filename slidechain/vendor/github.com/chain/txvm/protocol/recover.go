package protocol

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/state"
)

// Recover performs crash recovery, restoring the blockchain
// to a complete state. It returns the latest confirmed block
// and the corresponding state snapshot.
//
// If the blockchain is empty (missing initial block), this function
// returns a nil block and an empty snapshot.
func (c *Chain) Recover(ctx context.Context) (*state.Snapshot, error) {
	snapshot, err := c.store.LatestSnapshot(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "getting latest snapshot")
	}
	var b *bc.Block
	if snapshot.Height() > 0 {
		b, err = c.store.GetBlock(ctx, snapshot.Height())
		if err != nil {
			return nil, errors.Wrap(err, "getting snapshot block")
		}
		atomic.StoreUint64(&c.lastQueuedSnapshotHeight, b.Height)
	}
	if snapshot == nil {
		snapshot = state.Empty()
	}

	// The true height of the blockchain might be higher than the
	// height at which the state snapshot was taken. Replay all
	// existing blocks higher than the snapshot height.
	height, err := c.store.Height(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "getting blockchain height")
	}

	// Bring the snapshot up to date with the latest block
	for h := snapshot.Height() + 1; h <= height; h++ {
		b, err = c.store.GetBlock(ctx, h)
		if err != nil {
			return nil, errors.Wrap(err, "getting block")
		}
		err = snapshot.ApplyBlock(b.UnsignedBlock)
		if err != nil {
			return nil, errors.Wrap(err, "applying block")
		}
		if b.ContractsRoot.Byte32() != snapshot.ContractsTree.RootHash() {
			return nil, fmt.Errorf("block %d has contract root %x; snapshot has root %x",
				b.Height, b.ContractsRoot.Bytes(), snapshot.ContractsTree.RootHash())
		}
	}
	if b != nil {
		// All blocks before the latest one have been fully processed
		// (saved in the db, callbacks invoked). The last one may have
		// been too, but make sure just in case. Also "finalize" the last
		// block (notifying other processes of the latest block height)
		// and maybe persist the snapshot.
		err = c.CommitAppliedBlock(ctx, b, snapshot)
		if err != nil {
			return nil, errors.Wrap(err, "committing block")
		}
	}
	return snapshot, nil
}
