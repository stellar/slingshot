package main

import (
	"context"
	"database/sql"
	"time"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/state"
)

type blockStore struct {
	db      *sql.DB
	heights chan<- uint64
}

func newBlockStore(db *sql.DB, heights chan<- uint64) (*blockStore, error) {
	_, err := db.Exec(schema)
	if err != nil {
		return nil, errors.Wrap(err, "creating db schema")
	}

	var height uint64
	err = db.QueryRow("SELECT height FROM blocks ORDER BY height DESC LIMIT 1").Scan(&height)
	if err == sql.ErrNoRows {
		initialBlock, err := protocol.NewInitialBlock(nil, 0, time.Now())
		if err != nil {
			return nil, errors.Wrap(err, "producing genesis block")
		}
		h := initialBlock.Hash().Bytes()
		bits, err := initialBlock.Bytes()
		if err != nil {
			return nil, errors.Wrap(err, "marshaling genesis block for writing to db")
		}
		_, err = db.Exec("INSERT OR IGNORE INTO blocks (height, hash, bits) VALUES (1, $1, $2)", h, bits)
		if err != nil {
			return nil, errors.Wrap(err, "writing genesis block to db")
		}
	} else if err != nil {
		return nil, errors.Wrap(err, "getting blockchain height")
	}
	return &blockStore{
		db:      db,
		heights: heights,
	}, nil
}

func (s *blockStore) Height(context.Context) (uint64, error) {
	var height uint64
	err := s.db.QueryRow("SELECT MAX(height) FROM blocks").Scan(&height)
	return height, err
}

func (s *blockStore) GetBlock(_ context.Context, height uint64) (*bc.Block, error) {
	var bits []byte
	err := s.db.QueryRow("SELECT bits FROM blocks WHERE height = $1", height).Scan(&bits)
	if err != nil {
		return nil, errors.Wrapf(err, "reading block %d from db", height)
	}
	b := new(bc.Block)
	err = b.FromBytes(bits)
	return b, errors.Wrapf(err, "parsing block %d", height)
}

func (s *blockStore) LatestSnapshot(context.Context) (*state.Snapshot, error) {
	var bits []byte
	err := s.db.QueryRow("SELECT bits FROM snapshots ORDER BY height DESC LIMIT 1").Scan(&bits)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, errors.Wrap(err, "getting latest snapshot from db")
	}
	st := state.Empty()
	err = st.FromBytes(bits)
	return st, errors.Wrap(err, "parsing latest snapshot")
}

func (s *blockStore) SaveBlock(_ context.Context, b *bc.Block) error {
	h := b.Hash().Bytes()
	bits, err := b.Bytes()
	if err != nil {
		return errors.Wrapf(err, "marshaling block %d for writing to db", b.Height)
	}
	_, err = s.db.Exec("INSERT OR IGNORE INTO blocks (height, hash, bits) VALUES ($1, $2, $3)", b.Height, h, bits)
	return errors.Wrapf(err, "writing block %d to db", b.Height)
}

func (s *blockStore) FinalizeHeight(_ context.Context, height uint64) error {
	s.heights <- height
	return nil
}

func (s *blockStore) SaveSnapshot(_ context.Context, snapshot *state.Snapshot) error {
	bits, err := snapshot.Bytes()
	if err != nil {
		return errors.Wrapf(err, "marshaling snapshot at height %d for writing to db", snapshot.Height())
	}
	_, err = s.db.Exec("INSERT OR IGNORE INTO snapshots (height, bits) VALUES ($1, $2)", snapshot.Height(), bits)
	return errors.Wrapf(err, "writing snapshot at height %d to db", snapshot.Height())
}
