// Package op assigns human-readable names to numeric opcodes.
package op

import (
	"encoding/binary"
	"fmt"
)

//go:generate go run gen.go
//
// gen.go looks for the first const block in this file
// and produces opgen.go from it.

// Names for txvm opcodes.
// (These symbols use Go-style capitalization.
// The string mnemonics handled by functions Code and Name
// are all-lowercase, as in the spec.)
const (
	Int = 0x20
	Add = 0x21
	Neg = 0x22
	Mul = 0x23
	Div = 0x24
	Mod = 0x25
	GT  = 0x26
	Not = 0x27
	And = 0x28
	Or  = 0x29

	Roll    = 0x2a
	Bury    = 0x2b
	Reverse = 0x2c
	Get     = 0x2d
	Put     = 0x2e
	Depth   = 0x2f

	Nonce   = 0x30
	Merge   = 0x31
	Split   = 0x32
	Issue   = 0x33
	Retire  = 0x34
	Amount  = 0x35
	AssetID = 0x36
	Anchor  = 0x37

	VMHash   = 0x38
	SHA256   = 0x39
	SHA3     = 0x3a
	CheckSig = 0x3b

	Log      = 0x3c
	PeekLog  = 0x3d
	TxID     = 0x3e
	Finalize = 0x3f

	Verify          = 0x40
	JumpIf          = 0x41
	Exec            = 0x42
	Call            = 0x43
	Yield           = 0x44
	Wrap            = 0x45
	Input           = 0x46
	Output          = 0x47
	Contract        = 0x48
	Seed            = 0x49
	Self            = 0x4a
	Caller          = 0x4b
	ContractProgram = 0x4c
	TimeRange       = 0x4d

	Prv = 0x4e
	Ext = 0x4f

	Eq      = 0x50
	Dup     = 0x51
	Drop    = 0x52
	Peek    = 0x53
	Tuple   = 0x54
	Untuple = 0x55
	Len     = 0x56
	Field   = 0x57
	Encode  = 0x58
	Cat     = 0x59
	Slice   = 0x5a
	BitNot  = 0x5b
	BitAnd  = 0x5c
	BitOr   = 0x5d
	BitXor  = 0x5e
)

// The first few integers can be represented with dedicated
// opcodes. Outside of this range it's necessary to push the encoding
// of an integer as a byte string, then convert it to an integer with
// the "int" instruction.
const (
	// MinSmallInt is the smallest
	MinSmallInt = 0
	MaxSmallInt = 0x1f
)

// MinPushdata is the minimum opcode for immediate data instructions.
// All instructions with opcode >= MinPushdata contain immediate data
// of size opcode-MinPushdata. For example, the one-byte instruction
// 0x5f carries 0 bytes of immediate data, and the three-byte instruction
// 0x61 0x62 0x63 carries 0x61-0x5f = 2 bytes of immediate data
// (the ASCII letters 'b' and 'c').
//
// The choice of 0x5f for the beginning of the pushdata instructions
// means that the common operation of pushing a 32-byte string can
// be done with a single-byte pushdata prefix (0x7f). Because of
// varint encoding, the next opcode is two bytes long.
const MinPushdata = 0x5f

// Name returns the name of opcode.
func Name(opcode byte) string {
	// TODO(kr): return correct name for opcodes not in table
	return name[opcode]
}

// Code returns the opcode for the given name,
// or false if name is unknown.
func Code(name string) (byte, bool) {
	v, ok := code[name]
	return v, ok
}

// IsSmallIntOp tells whether the given opcode is one of the
// small-integer-encoding instructions.
func IsSmallIntOp(o byte) bool {
	return o >= MinSmallInt && o <= MaxSmallInt
}

// IsSmallInt tells whether the given integer can be encoded with a
// small-integer-encoding instruction.
func IsSmallInt(n int64) bool {
	return 0 <= n && n <= int64(MaxSmallInt-MinSmallInt)
}

// IsPushdataOp tells whether the given opcode is a pushdata
// instruction.
func IsPushdataOp(o byte) bool {
	return o >= MinPushdata
}

// DecodeInst decodes the first instruction in the given program.
//
// For non-pushdata instructions, DecodeInst returns (opcode, nil, 1, err).
//
// For pushdata instructions, DecodeInst returns (MinPushdata, data,
// n, err) where data is the immediate argument to the pushdata
// instruction (the bytes to be pushed) and n is the number of bytes
// of prog consumed by decoding this instruction.
func DecodeInst(prog []byte) (byte, []byte, int64, error) {
	if len(prog) == 0 {
		return 0, nil, 0, fmt.Errorf("empty program")
	}
	opcode, n := binary.Uvarint(prog)
	if n <= 0 {
		return 0, nil, 0, fmt.Errorf("invalid uvarint")
	}
	if opcode < uint64(MinPushdata) {
		return byte(opcode), nil, int64(n), nil
	}
	l := opcode - uint64(MinPushdata)
	r := uint64(n) + l
	if uint64(len(prog)) < r {
		return MinPushdata, nil, 0, fmt.Errorf("pushdata: only %d of %d bytes available", len(prog)-n, l)
	}
	return MinPushdata, append([]byte{}, prog[n:r]...), int64(r), nil
}
