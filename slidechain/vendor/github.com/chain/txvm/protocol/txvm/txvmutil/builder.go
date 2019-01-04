/*
Package txvmutil defines a "fluent" builder type for constructing TxVM
programs.
*/
package txvmutil

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/chain/txvm/protocol/txvm/op"
)

// Builder helps programmatically build txvm programs.
type Builder struct {
	buf bytes.Buffer
}

// TODO(jackson): Can we make this builder more ergonomic?
// https://github.com/interstellar/i10r/pull/2790#issuecomment-373210076

// Build returns the assembled txvm program.
func (b *Builder) Build() []byte {
	return b.buf.Bytes()
}

// PushdataBytes writes instructions to b,
// pushing data onto the stack.
func (b *Builder) PushdataBytes(data []byte) *Builder {
	writePushdata(&b.buf, data)
	return b
}

// PushdataByte writes instructions to b,
// pushing byt onto the stack.
func (b *Builder) PushdataByte(byt byte) *Builder {
	op := uint64(1 + int(op.MinPushdata))
	writeVarint(&b.buf, op)
	b.buf.WriteByte(byt)
	return b
}

// PushdataInt64 writes instructions to b pushing v
// onto the stack.
func (b *Builder) PushdataInt64(v int64) *Builder {
	writePushint64(&b.buf, v)
	return b
}

// PushdataInt64 writes instructions to b pushing v
// onto the stack.
// It panics if v does not fit in a int64.
func (b *Builder) PushdataUint64(v uint64) *Builder {
	if v > math.MaxInt64 {
		panic(fmt.Errorf("%d does not fit in int64", v))
	}
	b.PushdataInt64(int64(v))
	return b
}

// Concat concatenates an already assemble txvm program
// fragment onto the end of b.
func (b *Builder) Concat(prog []byte) *Builder {
	b.buf.Write(prog)
	return b
}

// Op writes the provided opcode to b.
func (b *Builder) Op(o byte) *Builder {
	b.buf.WriteByte(o)
	return b
}

// Tuple executes fn, passing in a TupleBuilder that exposes
// pushdata operations. All operations performed on the
// TupleBuilder during fn are shadowed to b.
// When fn completes, Tuple writes to b instructions to
// construct a tuple of the pushed data.
func (b *Builder) Tuple(fn func(*TupleBuilder)) *Builder {
	tb := TupleBuilder{b: b}
	fn(&tb)
	b.PushdataInt64(tb.count)
	b.Op(op.Tuple)
	return b
}

// TupleBuilder wraps a Builder, exposing only pushdata
// operations.
type TupleBuilder struct {
	b     *Builder
	count int64
}

// PushdataBytes writes instructions to b
// pushing data onto the stack.
func (tb *TupleBuilder) PushdataBytes(data []byte) *TupleBuilder {
	tb.b.PushdataBytes(data)
	tb.count++
	return tb
}

// PushdataByte writes instructions to b,
// pushing byt onto the stack.
func (tb *TupleBuilder) PushdataByte(byt byte) *TupleBuilder {
	tb.b.PushdataByte(byt)
	tb.count++
	return tb
}

// PushdataInt64 writes instructions to b pushing v
// onto the stack.
func (tb *TupleBuilder) PushdataInt64(v int64) *TupleBuilder {
	tb.b.PushdataInt64(v)
	tb.count++
	return tb
}

// Tuple executes fn, passing in a TupleBuilder that exposes
// pushdata operations. All operations performed on the
// TupleBuilder during fn are shadowed to tb's underlying Builder.
// When fn completes, Tuple writes to tb's underlying Builder
// instructions to construct a tuple of the pushed data.
func (tb *TupleBuilder) Tuple(fn func(*TupleBuilder)) *TupleBuilder {
	inner := TupleBuilder{b: tb.b}
	fn(&inner)
	tb.b.PushdataInt64(inner.count)
	tb.b.Op(op.Tuple)
	tb.count++
	return tb
}

func writeVarint(buf *bytes.Buffer, v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	buf.Write(tmp[:n])
}

func writePushdata(buf *bytes.Buffer, data []byte) {
	op := uint64(len(data) + int(op.MinPushdata))
	writeVarint(buf, op)
	buf.Write(data[:])
}

func writePushint64(buf *bytes.Buffer, num int64) {
	switch {
	case op.IsSmallInt(num):
		buf.WriteByte(op.MinSmallInt + byte(num))
	case num < 0 && num != math.MinInt64:
		writePushint64(buf, -num)
		buf.WriteByte(op.Neg)
	default:
		var tmp [binary.MaxVarintLen64]byte
		n := binary.PutUvarint(tmp[:], uint64(num))
		writePushdata(buf, tmp[:n])
		buf.WriteByte(op.Int)
	}
}
