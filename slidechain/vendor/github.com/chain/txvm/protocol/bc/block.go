package bc

import (
	"database/sql/driver"
	"encoding/hex"

	"github.com/golang/protobuf/proto"
	"golang.org/x/sync/errgroup"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/txvm"
)

// UnsignedBlock describes a block with its transactions but no signatures
// (predicate args).
type UnsignedBlock struct {
	*BlockHeader
	Transactions []*Tx
}

type Block struct {
	*UnsignedBlock
	Arguments []interface{}
}

// ErrTooFewSignatures is the error returned when Block.Sign cannot
// marshal enough signatures for a block.
var ErrTooFewSignatures = errors.New("too few block signatures")

// SignBlock produces a SignedBlock from a Block. It invokes its
// callback once for each position in [0..N) where N is the number of
// pubkeys in the previous block's NextPredicate, until a quorum of
// signatures is obtained.
//
// Any callback returning an error will cause SignBlock to return with an
// error. A callback may also return (nil, nil), causing it to be
// skipped silently. If too many callbacks do this, SignBlock will
// return ErrTooFewSignatures.
func SignBlock(b *UnsignedBlock, prev *BlockHeader, f func(int) (interface{}, error)) (*Block, error) {
	sb := &Block{UnsignedBlock: b}
	if b.Height == 1 {
		// Block at height 1 does not require a signature.
		return sb, nil
	}
	if prev == nil {
		return nil, errors.New("must supply previous blockheader to Sign")
	}
	pred := prev.NextPredicate
	if pred == nil {
		return nil, errors.New("no next predicate in previous blockheader")
	}
	if pred.Version != 1 {
		return nil, errors.New("unknown predicate version")
	}
	sb.Arguments = make([]interface{}, len(pred.Pubkeys))
	q := pred.Quorum
	if q > 0 && f == nil {
		return nil, errors.New("no signature function provided")
	}
	for i := 0; q > 0 && i < len(pred.Pubkeys); i++ {
		arg, err := f(i)
		if err != nil {
			return nil, errors.Wrapf(err, "getting signature %d for block %d", i, b.Height)
		}
		if arg == nil {
			continue
		}
		if sig, ok := arg.([]byte); ok {
			if len(sig) > 0 {
				sb.Arguments[i] = sig
				q--
			}
			continue
		}
		return nil, errors.New("non-signature in block arguments")
	}
	if q > 0 {
		return nil, ErrTooFewSignatures
	}
	return sb, nil
}

// MarshalText fulfills the json.Marshaler interface.
// This guarantees that blocks will get deserialized correctly
// when being parsed from HTTP requests.
func (b *Block) MarshalText() ([]byte, error) {
	bits, err := b.Bytes()
	if err != nil {
		return nil, err
	}

	enc := make([]byte, hex.EncodedLen(len(bits)))
	hex.Encode(enc, bits)
	return enc, nil
}

// UnmarshalText fulfills the encoding.TextUnmarshaler interface.
func (b *Block) UnmarshalText(text []byte) error {
	decoded := make([]byte, hex.DecodedLen(len(text)))
	_, err := hex.Decode(decoded, text)
	if err != nil {
		return err
	}
	return b.FromBytes(decoded)
}

// Scan fulfills the sql.Scanner interface.
func (b *Block) Scan(val interface{}) error {
	driverBuf, ok := val.([]byte)
	if !ok {
		return errors.New("Scan must receive a byte slice")
	}
	buf := make([]byte, len(driverBuf))
	copy(buf[:], driverBuf)
	return b.FromBytes(buf)
}

// Value fulfills the sql.driver.Valuer interface.
func (b *Block) Value() (driver.Value, error) {
	return b.Bytes()
}

// FromBytes parses a Block from a byte slice, by unmarshaling and
// converting a RawBlock protobuf.
func (b *Block) FromBytes(bits []byte) error {
	var rb RawBlock
	err := proto.Unmarshal(bits, &rb)
	if err != nil {
		return err
	}
	txs := make([]*Tx, len(rb.Transactions))
	var eg errgroup.Group
	for i := range rb.Transactions {
		i := i
		eg.Go(func() error {
			tx, err := NewTx(rb.Transactions[i].Program, rb.Transactions[i].Version, rb.Transactions[i].Runlimit)
			if err != nil {
				return err
			}
			if !tx.Finalized {
				return txvm.ErrUnfinalized
			}
			txs[i] = tx
			return nil
		})
	}
	err = eg.Wait()
	if err != nil {
		return err
	}
	b.UnsignedBlock = &UnsignedBlock{
		BlockHeader:  rb.Header,
		Transactions: txs,
	}
	for _, arg := range rb.Arguments {
		switch arg.Type {
		case DataType_BYTES:
			b.Arguments = append(b.Arguments, arg.Bytes)
		case DataType_INT:
			b.Arguments = append(b.Arguments, arg.Int)
		case DataType_TUPLE:
			b.Arguments = append(b.Arguments, arg.Tuple)
		}
	}
	return nil
}

// Bytes encodes the Block as a byte slice, by converting it to a
// RawBlock protobuf and marshaling that.
func (b *Block) Bytes() ([]byte, error) {
	var txs []*RawTx
	for _, tx := range b.Transactions {
		txs = append(txs, &RawTx{
			Version:  tx.Version,
			Runlimit: tx.Runlimit,
			Program:  tx.Program,
		})
	}
	var args []*DataItem
	for _, arg := range b.Arguments {
		switch a := arg.(type) {
		case []byte:
			args = append(args, &DataItem{Type: DataType_BYTES, Bytes: a})
		case int64:
			args = append(args, &DataItem{Type: DataType_INT, Int: a})
		case []*DataItem:
			args = append(args, &DataItem{Type: DataType_TUPLE, Tuple: a})
		}
	}
	rb := &RawBlock{
		Header:       b.BlockHeader,
		Transactions: txs,
		Arguments:    args,
	}
	return proto.Marshal(rb)
}
