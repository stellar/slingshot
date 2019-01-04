package txvm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/txvm/op"
)

// Item is an interface for all txvm stack items.
type Item interface {
	inspect() Tuple
	String() string
	isPortable() bool
	isDroppable() bool
}

// Data is an interface for plain-old-data stack items.
type Data interface {
	Item
	encode(*bytes.Buffer)
}

type (
	// Int is a stack item containing a 64-bit signed integer.
	Int int64

	// Bytes is a stack item containing a sequence of bytes.
	Bytes []byte

	// Tuple is a stack item containing a sequence of zero or more Data items.
	Tuple []Data
)

// Type codes for inspected data items.
const (
	IntCode   byte = 'Z'
	BytesCode byte = 'S'
	TupleCode byte = 'T'
)

func (i Int) inspect() Tuple   { return Tuple{Bytes{IntCode}, i} }
func (b Bytes) inspect() Tuple { return Tuple{Bytes{BytesCode}, b} }
func (t Tuple) inspect() Tuple { return Tuple{Bytes{TupleCode}, t} }

func (i Int) isPortable() bool   { return true }
func (b Bytes) isPortable() bool { return true }
func (t Tuple) isPortable() bool { return true }

func (i Int) isDroppable() bool   { return true }
func (b Bytes) isDroppable() bool { return true }
func (t Tuple) isDroppable() bool { return true }

func (i Int) encode(w *bytes.Buffer) {
	if op.IsSmallInt(int64(i)) {
		w.WriteByte(op.MinSmallInt + byte(i))
		return
	}
	var buf [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(buf[:], uint64(i))
	writePushdata(w, buf[:n])
	w.WriteByte(op.Int)
}

func (b Bytes) encode(w *bytes.Buffer) {
	writePushdata(w, b)
}

func (t Tuple) encode(w *bytes.Buffer) {
	for _, item := range t {
		item.encode(w)
	}
	Int(len(t)).encode(w)
	w.WriteByte(op.Tuple)
}

func (i Int) String() string {
	return fmt.Sprintf("%d", i)
}

func (b Bytes) String() string {
	for _, x := range b {
		if x < 0x20 || x >= 0x7f {
			// Note: unicode.IsPrint(rune(x)) produces surprising results.
			// E.g. 0x01 and 0xff are "printable" and we would emit '?'.
			return fmt.Sprintf("x'%x'", []byte(b))
		}
	}
	return fmt.Sprintf("'%s'", string(b))
}

func (t Tuple) String() string {
	var strs []string
	for _, item := range t {
		strs = append(strs, item.String())
	}
	return fmt.Sprintf("{%s}", strings.Join(strs, ", "))
}

// Encode serializes an arbitrary data type in a program,
// which, when executed, produces that data.
func Encode(v Data) []byte {
	var b bytes.Buffer
	v.encode(&b)
	return b.Bytes()
}

func writePushdata(buf *bytes.Buffer, data []byte) {
	op := uint64(len(data)) + op.MinPushdata
	varint := [binary.MaxVarintLen64]byte{}
	n := binary.PutUvarint(varint[:], op)
	buf.Write(varint[:n])
	buf.Write(data[:])
}

func uninspect(t Tuple) (Item, error) {
	if len(t) == 0 {
		return nil, errors.WithData(ErrFields, "got", "empty tuple in uninspect")
	}
	code, ok := t[0].(Bytes)
	if !ok || len(code) != 1 {
		return nil, errors.WithData(ErrFields, "want", "typecode", "got", t[0])
	}
	switch code[0] {
	case IntCode:
		v, ok := t[1].(Int)
		if !ok {
			return nil, errors.WithData(ErrFields, "want", "int", "got", t[1])
		}
		return v, nil
	case BytesCode:
		v, ok := t[1].(Bytes)
		if !ok {
			return nil, errors.WithData(ErrFields, "want", "bytes", "got", t[1])
		}
		return v, nil
	case TupleCode:
		v, ok := t[1].(Tuple)
		if !ok {
			return nil, errors.WithData(ErrFields, "want", "tuple", "got", t[1])
		}
		return v, nil
	case ValueCode:
		var v value
		err := v.uninspect(t)
		return &v, errors.Wrap(err, "uninspecting value")
	case ContractCode, WrappedContractCode:
		var v contract
		err := v.uninspect(t)
		return &v, errors.Wrap(err, "uninspecting contract")
	}
	return nil, errors.WithData(ErrFields, "want", "typecode", "got", t[0])
}
