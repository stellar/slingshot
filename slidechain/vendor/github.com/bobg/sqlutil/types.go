package sqlutil

import (
	"context"
	"database/sql"
)

type (
	PreparerContext interface {
		PrepareContext(context.Context, string) (*sql.Stmt, error)
	}

	QueryerContext interface {
		QueryContext(context.Context, string, ...interface{}) (*sql.Rows, error)
		QueryRowContext(context.Context, string, ...interface{}) *sql.Row
	}

	ExecerContext interface {
		ExecContext(context.Context, string, ...interface{}) (sql.Result, error)
	}

	DB interface {
		PreparerContext
		QueryerContext
		ExecerContext
		Begin() (*sql.Tx, error)
	}
)
