package store

import (
	"context"
	"database/sql"
	"log"
	"time"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol"
	"github.com/chain/txvm/protocol/bc"
	"github.com/chain/txvm/protocol/state"
)

type BlockStore struct {
	db      *sql.DB
	heights chan<- uint64
}

func New(db *sql.DB, heights chan<- uint64) (*BlockStore, error) {
	var height uint64
	err := db.QueryRow("SELECT height FROM blocks ORDER BY height DESC LIMIT 1").Scan(&height)
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
	return &BlockStore{
		db:      db,
		heights: heights,
	}, nil
}

func (s *BlockStore) Height(context.Context) (uint64, error) {
	var height uint64
	err := s.db.QueryRow("SELECT MAX(height) FROM blocks").Scan(&height)
	return height, err
}

func (s *BlockStore) GetBlock(_ context.Context, height uint64) (*bc.Block, error) {
	var bits []byte
	err := s.db.QueryRow("SELECT bits FROM blocks WHERE height = $1", height).Scan(&bits)
	if err != nil {
		return nil, errors.Wrapf(err, "reading block %d from db", height)
	}
	b := new(bc.Block)
	err = b.FromBytes(bits)
	return b, errors.Wrapf(err, "parsing block %d", height)
}

func (s *BlockStore) LatestSnapshot(context.Context) (*state.Snapshot, error) {
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

func (s *BlockStore) SaveBlock(_ context.Context, b *bc.Block) error {
	h := b.Hash().Bytes()
	bits, err := b.Bytes()
	if err != nil {
		return errors.Wrapf(err, "marshaling block %d for writing to db", b.Height)
	}
	_, err = s.db.Exec("INSERT OR IGNORE INTO blocks (height, hash, bits) VALUES ($1, $2, $3)", b.Height, h, bits)
	return errors.Wrapf(err, "writing block %d to db", b.Height)
}

func (s *BlockStore) FinalizeHeight(_ context.Context, height uint64) error {
	s.heights <- height
	return nil
}

func (s *BlockStore) SaveSnapshot(_ context.Context, snapshot *state.Snapshot) error {
	bits, err := snapshot.Bytes()
	if err != nil {
		return errors.Wrapf(err, "marshaling snapshot at height %d for writing to db", snapshot.Height())
	}
	_, err = s.db.Exec("INSERT OR IGNORE INTO snapshots (height, bits) VALUES ($1, $2)", snapshot.Height(), bits)
	return errors.Wrapf(err, "writing snapshot at height %d to db", snapshot.Height())
}

// ExpireBlocks runs as a goroutine,
// periodically removing blocks from the db when they are no longer needed.
// A block is needed if any existing pin has not processed it yet,
// or if no snapshot is stored at or above its height.
// The initial block and the latest block are always needed.
func (s *BlockStore) ExpireBlocks(ctx context.Context) {
	defer log.Print("ExpireBlocks exiting")

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			snap, err := s.LatestSnapshot(ctx)
			if err != nil {
				log.Printf("error getting latest snapshot in ExpireBlocks: %s", err)
				continue
			}

			height := snap.Header.Height

			const q = `SELECT MIN(height) FROM pins`
			var lowestPin uint64
			err = s.db.QueryRowContext(ctx, q).Scan(&lowestPin)
			if err != nil {
				log.Printf("error getting lowest pin in ExpireBlocks: %s", err)
				continue
			}
			if lowestPin < height {
				height = lowestPin
			}

			if height > 2 {
				log.Printf("deleting blocks 2 through %d from the db", height-1)
				_, err = s.db.ExecContext(ctx, `DELETE FROM blocks WHERE height > 1 AND height < $1`, height)
				if err != nil {
					log.Printf("error expiring blocks: %s", err)
				}
			}
		}
	}
}
