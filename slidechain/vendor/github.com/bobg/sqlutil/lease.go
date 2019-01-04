package sqlutil

// The code in this file is adapted from similar code in
// https://github.com/chain/chain/tree/1.2-stable/core/leader.

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"
)

type LeaseKeyType [16]byte

// Lease represents the exclusive acquisition of a resource until a certain deadline.
type Lease struct {
	Ctx, ParentCtx context.Context
	Cancel         context.CancelFunc
	DB             ExecerContext
	Table          string
	Key            LeaseKeyType
}

var ErrNoUpdate = errors.New("no rows updated")

// NewLease attempts to acquire a lease from a given DB table for a
// given amount of time.
//
// The table must have a column "lease_key" to hold a 16-byte string;
// a column "lease_expiration" to hold a timestamp (a DATETIME); and
// column defined like:
//   singleton BOOL NOT NULL UNIQUE CHECK (singleton) DEFAULT true
// which ensures the table can only ever contain a single row.
func NewLease(ctx context.Context, db ExecerContext, table string, dur time.Duration) (*Lease, error) {
	now := time.Now()

	const delQFmt = `DELETE FROM %s WHERE lease_expiration < $1`
	delQ := fmt.Sprintf(delQFmt, table)
	_, err := db.ExecContext(ctx, delQ, now)
	if err != nil {
		return nil, err
	}

	var key LeaseKeyType
	_, err = rand.Read(key[:])
	if err != nil {
		return nil, err
	}

	exp := now.Add(dur)

	const insQFmt = `INSERT INTO %s (lease_key, lease_expiration) VALUES ($1, $2)`
	insQ := fmt.Sprintf(insQFmt, table)
	_, err = db.ExecContext(ctx, insQ, key[:], exp)
	if err != nil {
		return nil, err
	}

	ctx2, cancel := context.WithDeadline(ctx, exp)

	l := &Lease{
		ParentCtx: ctx,
		Ctx:       ctx2,
		Cancel:    cancel,
		DB:        db,
		Table:     table,
		Key:       key,
	}
	return l, nil
}

func (l *Lease) End() error {
	l.Cancel()
	const delQFmt = `DELETE FROM %s WHERE lease_key = $1`
	delQ := fmt.Sprintf(delQFmt, l.Table)
	_, err := l.DB.ExecContext(l.ParentCtx, delQ, l.Key[:])
	return err
}

func (l *Lease) Renew(dur time.Duration) error {
	now := time.Now()
	exp := now.Add(dur)

	const updQFmt = `UPDATE %s SET lease_expiration = $1 WHERE key = $2 AND lease_expiration < $3`
	updQ := fmt.Sprintf(updQFmt, l.Table)
	res, err := l.DB.ExecContext(l.Ctx, updQ, exp, l.Key[:], now)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNoUpdate
	}
	l.Cancel()
	ctx, cancel := context.WithDeadline(l.ParentCtx, exp)
	l.Ctx = ctx
	l.Cancel = cancel
	return nil
}
