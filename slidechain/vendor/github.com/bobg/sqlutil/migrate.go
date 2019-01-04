package sqlutil

import (
	"context"
	"crypto/sha256"
	"errors"
)

var ErrMisorderedMigrations = errors.New("misordered migrations")

// Migrate executes database migrations.
func Migrate(ctx context.Context, db DB, migrations []string) error {
	const appliedQ = `SELECT hash FROM migrations`
	applied := make(map[string]bool)
	err := ForQueryRows(ctx, db, appliedQ, func(h []byte) {
		applied[string(h)] = true
	})
	if err != nil {
		return err
	}

	var unapplied []string
	for _, m := range migrations {
		h := sha256.Sum256([]byte(m))
		hs := string(h[:])
		if applied[hs] {
			if len(unapplied) > 0 {
				return ErrMisorderedMigrations
			}
		} else {
			unapplied = append(unapplied, m)
		}
	}

	for _, m := range unapplied {
		err = func() error {
			dbtx, err := db.Begin()
			if err != nil {
				return err
			}
			defer dbtx.Rollback()

			_, err = dbtx.ExecContext(ctx, m)
			if err != nil {
				return err
			}

			h := sha256.Sum256([]byte(m))

			const addQ = `INSERT INTO migrations (hash) VALUES ($1)`
			_, err = dbtx.ExecContext(ctx, addQ, h[:])
			if err != nil {
				return err
			}

			err = dbtx.Commit()
			return err
		}()
		if err != nil {
			return err
		}
	}

	return nil
}
