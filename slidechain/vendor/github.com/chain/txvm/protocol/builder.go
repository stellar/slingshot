package protocol

import (
	"fmt"
	"time"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/math/checked"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/merkle"
	"github.com/chain/txvm/protocol/state"
)

// Some defaults.
const (
	maxNonceWindow = 24 * time.Hour
	maxBlockWindow = 600
	maxBlockTxs    = 10000
)

type BlockBuilder struct {
	Version        uint64
	MaxNonceWindow time.Duration
	MaxBlockWindow int64
	MaxBlockTxs    int

	snapshot    *state.Snapshot
	txs         []*bc.CommitmentsTx
	timestampMS uint64
	runlimit    int64
}

func NewBlockBuilder() *BlockBuilder {
	return &BlockBuilder{
		Version:        3,
		MaxNonceWindow: maxNonceWindow,
		MaxBlockWindow: maxBlockWindow,
		MaxBlockTxs:    maxBlockTxs,
	}
}

func (bb *BlockBuilder) Start(snapshot *state.Snapshot, timestampMS uint64) error {
	if timestampMS <= snapshot.Header.TimestampMs {
		return fmt.Errorf("timestamp %d is not greater than prevblock timestamp %d", timestampMS, snapshot.Header.TimestampMs)
	}
	bb.snapshot = state.Copy(snapshot)
	bb.snapshot.PruneNonces(timestampMS)
	bb.timestampMS = timestampMS
	bb.txs = nil
	bb.runlimit = 0
	return nil
}

var (
	// ErrBlockFull happens when trying to add a transaction to a block
	// that already contains MaxBlockTxs transactions.
	ErrBlockFull = errors.New("block is full")

	// ErrBlockRunlimit happens when trying to add a transaction to a
	// block that would cause the block's total runlimit to overflow.
	ErrBlockRunlimit = errors.New("block runlimit overflow")

	// ErrTxTooOld happens when trying to add a transaction to a block
	// whose timestamp is after the end of a timerange in the
	// transaction.
	ErrTxTooOld = errors.New("transaction timerange is in the past")

	// ErrTxTooNew happens when trying to add a transaction to a block
	// whose timestamp is before the beginning of a timerange in the
	// transaction.
	ErrTxTooNew = errors.New("transaction timerange is in the future")

	// ErrTxLongNonce happens when trying to add a transaction with a
	// nonce whose expiration is more than MaxNonceWindow in the future.
	ErrTxLongNonce = errors.New("transaction nonce expires too far in the future")
)

func (bb *BlockBuilder) AddTx(tx *bc.CommitmentsTx) error {
	if len(bb.txs) >= bb.MaxBlockTxs {
		return ErrBlockFull
	}
	err := bb.checkTransactionTime(tx.Tx, bb.timestampMS)
	if err != nil {
		return err
	}
	runlimit, ok := checked.AddInt64(bb.runlimit, tx.Tx.Runlimit)
	if !ok {
		return ErrBlockRunlimit
	}
	err = bb.snapshot.ApplyTx(tx)
	if err != nil {
		return err
	}

	bb.runlimit = runlimit
	bb.txs = append(bb.txs, tx)

	return nil
}

func (bb *BlockBuilder) Build() (*bc.UnsignedBlock, *state.Snapshot, error) {
	prev := bb.snapshot.Header
	refsCount := bb.MaxBlockWindow
	if prev.RefsCount < refsCount {
		refsCount = prev.RefsCount + 1
	}

	var (
		txs = make([]*bc.Tx, 0, len(bb.txs))
		wcs = make([][]byte, 0, len(bb.txs))
	)
	for _, tx := range bb.txs {
		txs = append(txs, tx.Tx)
		wcs = append(wcs, tx.WitnessCommitment)
	}

	var (
		txRoot        = bc.NewHash(merkle.Root(wcs))
		contractsRoot = bc.NewHash(bb.snapshot.ContractsTree.RootHash())
		nonceRoot     = bc.NewHash(bb.snapshot.NonceTree.RootHash())
	)

	prevID := prev.Hash()
	h := &bc.BlockHeader{
		Version:          bb.Version,
		Height:           prev.Height + 1,
		PreviousBlockId:  &prevID,
		TimestampMs:      bb.timestampMS,
		RefsCount:        refsCount,
		NextPredicate:    prev.NextPredicate,
		Runlimit:         bb.runlimit,
		TransactionsRoot: &txRoot,
		ContractsRoot:    &contractsRoot,
		NoncesRoot:       &nonceRoot,
	}
	b := &bc.UnsignedBlock{
		BlockHeader:  h,
		Transactions: txs,
	}
	err := bb.snapshot.ApplyBlockHeader(h)
	if err != nil {
		return nil, nil, err
	}

	snapshot := bb.snapshot
	bb.snapshot = nil
	bb.txs = nil
	bb.timestampMS = 0
	bb.runlimit = 0

	return b, snapshot, nil
}

// checkTransactionTime ensures that a transaction is fit
// to be included in a block generated at blockTimeMS.
func (bb *BlockBuilder) checkTransactionTime(tx *bc.Tx, blockTimeMS uint64) error {
	for _, tr := range tx.Timeranges {
		if tr.MaxMS > 0 && blockTimeMS > uint64(tr.MaxMS) {
			return ErrTxTooOld
		}
		if tr.MinMS > 0 && blockTimeMS > 0 && blockTimeMS < uint64(tr.MinMS) {
			return ErrTxTooNew
		}
	}

	if bb.MaxNonceWindow > 0 {
		for _, nonce := range tx.Nonces {
			if nonce.ExpMS > bc.DurationMillis(bb.MaxNonceWindow)+blockTimeMS {
				return ErrTxLongNonce
			}
		}
	}
	return nil
}
