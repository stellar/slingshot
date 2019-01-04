package sqlutil

import "context"

type ctxkeytype string

var ctxkey = ctxkeytype("db")

func WithDB(ctx context.Context, db DB) context.Context {
	return context.WithValue(ctx, ctxkey, db)
}

func GetDB(ctx context.Context) DB {
	return ctx.Value(ctxkey).(DB)
}
