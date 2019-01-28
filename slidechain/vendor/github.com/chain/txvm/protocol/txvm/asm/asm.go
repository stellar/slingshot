package asm

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/chain/txvm/errors"
	"github.com/chain/txvm/protocol/txvm"
	"github.com/chain/txvm/protocol/txvm/op"
)

type jump struct {
	label    string
	isJumpIf bool
	opcodes  []byte
}

type macro struct {
	ident     string
	expansion string
}

var macros = []macro{
	{ident: "bool", expansion: "not not"},
	{ident: "swap", expansion: "1 roll"},
	{ident: "jump", expansion: "1 swap jumpif"},
	{ident: "le", expansion: "gt not"},
	{ident: "ge", expansion: "swap le"},
	{ident: "lt", expansion: "swap gt"},
	{ident: "sub", expansion: "neg add"},
	{ident: "splitzero", expansion: "0 split"},
}

// initialized in init()
var decomposite map[string]string
var composite map[string][]byte

// Notation:
//    word          mnemonic
//   12345          number
//   x'aa' or x"aa" hex data
//   'foo' or "foo" string
//   [dup]          quoted program
//   {x, y, z}      tuple (encoded as "push z, push y, push x, push 3, 'tuple'")
//   $label         jump target
//   jumpif:$label  conditional jump to target
//   jump:$label    unconditional jump to target

// Assemble converts a string containing an assembly language txvm
// program into the corresponding bytecode.
func Assemble(s string) ([]byte, error) {
	scan := new(scanner)
	scan.initString(s)
	bytecode, err := assemble(scan, tokEOF)

	// prefer the scanner's errors over the assemblers.
	if len(scan.errs) > 0 {
		return nil, errors.WithData(
			errors.New("scanner error"),
			"errors",
			scan.errs)
	}
	return bytecode, err
}

// MustAssemble calls Assemble and panics on error.
func MustAssemble(s string) []byte {
	result, err := Assemble(s)
	if err != nil {
		panic(err)
	}
	return result
}

func assemble(s *scanner, stoptok token) ([]byte, error) {
	// First construct a list of assembler "items," then "resolve" those
	// into bytecode.
	//
	// "Items" are:
	//   - symbolic jumps,
	//   - symbolic jumpifs,
	//   - symbolic jumptargets, and
	//   - (other) instruction sequences.
	a := &assembler{
		stoptok: stoptok,
		scanner: s,
	}
	err := a.assembleItems()
	if err != nil {
		return nil, err
	}
	return resolve(a.items)
}

type assembler struct {
	stoptok token // token to stop scanning at
	scanner *scanner
	off     int
	tok     token
	lit     string

	items []interface{}
	buf   bytes.Buffer // current item
}

func (a *assembler) next() token {
	a.off, a.tok, a.lit = a.scanner.scan()
	for a.tok == tokComment {
		a.off, a.tok, a.lit = a.scanner.scan()
	}
	return a.tok
}

func (a *assembler) flush() {
	if a.buf.Len() == 0 {
		return
	}
	b := make([]byte, a.buf.Len())
	copy(b[:], a.buf.Bytes())
	a.items = append(a.items, b)
	a.buf.Reset()
}

func (a *assembler) assembleItems() error {
	for a.next() != a.stoptok {
		switch a.tok {
		case tokLabel:
			a.flush()
			a.items = append(a.items, a.lit[1:])
		case tokJump, tokJumpIf:
			a.flush()
			jmp := jump{isJumpIf: a.tok == tokJumpIf}

			// must be followed with a label
			if a.next() != tokLabel {
				return fmt.Errorf("expected label at offset %d", a.off)
			}
			jmp.label = a.lit[1:]
			a.items = append(a.items, &jmp)
		case tokIdent:
			if preassembled, ok := composite[a.lit]; ok {
				a.buf.Write(preassembled)
			} else if o, ok := op.Code(a.lit); ok {
				a.buf.WriteByte(o)
			} else {
				return fmt.Errorf("unknown identifier %q at offset %d", a.lit, a.off)
			}

		default:
			err := a.assembleValue()
			if err != nil {
				return err
			}
		}
	}
	a.flush()
	return nil
}

func (a *assembler) assembleValue() error {
	switch a.tok {
	case tokString:
		data := a.lit[1 : len(a.lit)-1]

		op := uint64(len(data) + int(op.MinPushdata))
		writeVarint(&a.buf, op)
		a.buf.WriteString(data)
	case tokHex:
		hexstr := a.lit[2 : len(a.lit)-1]
		data, err := hex.DecodeString(hexstr)
		if err != nil {
			return errors.Wrapf(err, "offset %d", a.off)
		}
		writePushdata(&a.buf, data)
	case tokNumber:
		signed, err := strconv.ParseInt(a.lit, 10, 64)
		if err != nil {
			return err
		}
		writePushint64(&a.buf, signed)
	case tokLeftBrace:
		// assemble values until we see a right brace
		var count int64 = 0
		for tok := a.next(); tok != tokRightBrace; tok = a.next() {
			if count > 0 {
				if tok != tokComma {
					return fmt.Errorf("expected ',' at offset %d, found %q", a.off, a.lit)
				}
				a.next()
			}

			count++
			err := a.assembleValue()
			if err != nil {
				return err
			}
		}
		writePushint64(&a.buf, count)
		a.buf.WriteByte(op.Tuple)
	case tokLeftBracket:
		prog, err := assemble(a.scanner, tokRightBracket)
		if err != nil {
			return err
		}
		writePushdata(&a.buf, prog)
	default:
		return fmt.Errorf("unexpected token %q at offset %d", a.lit, a.off)
	}
	return nil
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

func writeVarint(buf *bytes.Buffer, v uint64) {
	var tmp [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(tmp[:], v)
	buf.Write(tmp[:n])
}

func resolve(items []interface{}) ([]byte, error) {
	labelIdxs := make(map[string]int) // index within items of each jump label
	for i, item := range items {
		if l, ok := item.(string); ok {
			labelIdxs[l] = i
		}
	}

	// Each jump starts with a 0-byte opcode expansion.  The distance to
	// each jumptarget starts as an estimate, because of possible
	// intervening jumps whose final opcode lengths are not yet
	// determined. Keep refining the jumps until no jumps need further
	// refinement.

	again := true
	for again {
		again = false
		for i, item := range items {
			if j, ok := item.(*jump); ok {
				labelIdx, ok := labelIdxs[j.label]
				if !ok {
					return nil, fmt.Errorf("jump to unknown label $%s", j.label)
				}
				// Count the bytes of the intervening items between i and labelIdx
				var (
					rel  int64
					a, b int
				)
				if labelIdx < i {
					a, b = labelIdx, i
				} else {
					a, b = i, labelIdx
				}
				for k := a + 1; k < b; k++ {
					switch kk := items[k].(type) {
					case []byte:
						rel += int64(len(kk))
					case *jump:
						rel += int64(len(kk.opcodes))
					}
				}
				if labelIdx < i {
					rel = -rel - 1 // the -1 is for jumping backward over the jumpif instruction
				}
				var opcodes []byte
				if !j.isJumpIf {
					opcodes = pushint64(1)
					if labelIdx < i {
						rel -= int64(len(opcodes))
					}
				}
				if labelIdx < i {
					// Have to adjust rel to jump backward over the pushdata
					// encoding of rel. Iteratively refine it.
					var reladj int

					for {
						pushrel := pushint64(rel - int64(reladj))
						if len(pushrel) == reladj {
							break
						}
						reladj = len(pushrel)
					}

					rel -= int64(reladj)
				}
				opcodes = append(opcodes, pushint64(rel)...)
				opcodes = append(opcodes, op.JumpIf)
				if !bytes.Equal(opcodes, j.opcodes) {
					j.opcodes = opcodes
					again = true
				}
			}
		}
	}
	var buf bytes.Buffer
	for _, item := range items {
		switch ii := item.(type) {
		case []byte:
			buf.Write(ii)
		case *jump:
			buf.Write(ii.opcodes)
		}
	}
	return buf.Bytes(), nil
}

func pushint64(num int64) []byte {
	if op.IsSmallInt(num) {
		return []byte{op.MinSmallInt + byte(num)}
	}
	if num < 0 && num != math.MinInt64 {
		return append(pushint64(-num), op.Neg)
	}
	var buf [10]byte
	n := binary.PutUvarint(buf[:], uint64(num))
	return append(pushdata(buf[:n]), op.Int)
}

// Disassemble converts a txvm bytecode program into an
// assembly-language representation.
//
// Sequences of instructions that can be abbreviated as one of the
// assembler's convenience macros are so abbreviated.
//
// Jumps are left in relative-addressing form. Symbolic jump targets
// are not created for them.
// TODO(bobg): might be nice to make them symbolic.
func Disassemble(prog []byte) (string, error) {
	pc := int64(0)

	var pieces []string

	var (
		pushdatas   = int64(0) // number of consecutive pushdatas, reset by a non-pushdata
		latestInt64 *int64
	)

	for pc < int64(len(prog)) {
		opcode, data, n, err := op.DecodeInst(prog[pc:])
		if err != nil {
			return "", err
		}
		pc += n
		switch {
		case op.IsSmallIntOp(opcode):
			val := int64(opcode - op.MinSmallInt)
			if pc < int64(len(prog)) && prog[pc] == op.Neg {
				val = -val
				pc++
			}
			pieces = append(pieces, fmt.Sprintf("%d", val))
			pushdatas++
			latestInt64 = &val
		case op.IsPushdataOp(opcode):
			done := false
			if pc < int64(len(prog)) {
				// Special handling for non-smallints (pushdata followed by `int` instruction)
				if len(data) > 0 && prog[pc] == op.Int {
					res, nbytes := binary.Uvarint(data)
					if nbytes == len(data) {
						pc++
						num := int64(res)
						if pc < int64(len(prog)) && prog[pc] == op.Neg {
							num = -num
							pc++
						}
						pieces = append(pieces, fmt.Sprintf("%d", num))
						latestInt64 = &num
						done = true
					}
				} else {
					switch prog[pc] {
					case op.Contract, op.Exec, op.Wrap, op.Yield, op.Output:
						prog, err := Disassemble(data)
						if err != nil {
							pieces = append(pieces, txvm.Bytes(data).String())
						} else {
							pieces = append(pieces, fmt.Sprintf("[%s]", prog))
						}
						done = true
					}
				}
			}
			if !done {
				pieces = append(pieces, txvm.Bytes(data).String())
				latestInt64 = nil
			}
			pushdatas++
		case opcode == op.Tuple:
			if latestInt64 != nil && *latestInt64 < pushdatas {
				t := "{"
				for i := int64(0); i < *latestInt64; i++ {
					if i != 0 {
						t += ", "
					}
					t += pieces[int64(len(pieces))-*latestInt64+i-1]
				}
				t += "}"
				pieces = pieces[:int64(len(pieces))-(*latestInt64+1)]
				pieces = append(pieces, t)
				pushdatas -= *latestInt64
			} else {
				pieces = append(pieces, op.Name(opcode))
				pushdatas = 1
			}
			latestInt64 = nil
		case int(opcode) < op.MinPushdata:
			pieces = append(pieces, op.Name(opcode))
			pushdatas = 0
			latestInt64 = nil
		default:
			return "", fmt.Errorf("invalid opcode %d", opcode)
		}

		repeat := true
		for repeat {
			repeat = false
			for k, v := range decomposite {
				ops := strings.Fields(k)
				for pieceIdx := 0; pieceIdx <= len(pieces)-len(ops); pieceIdx++ {
					match := true
					for opIdx := 0; opIdx < len(ops); opIdx++ {
						if pieces[pieceIdx+opIdx] != ops[opIdx] {
							match = false
							break
						}
					}
					if match {
						before := pieces[:pieceIdx]
						after := pieces[pieceIdx+len(ops):]
						pieces = append(before, v)
						pieces = append(pieces, after...)
						repeat = true
						break
					}
				}
				if repeat {
					break
				}
			}
		}
	}

	return strings.Join(pieces, " "), nil
}

func pushdata(data []byte) []byte {
	buf := [binary.MaxVarintLen64]byte{}
	n := binary.PutUvarint(buf[:], uint64(len(data)+int(op.MinPushdata)))
	return append(buf[:n], data...)
}

func init() {
	decomposite = make(map[string]string)
	composite = make(map[string][]byte)
	for _, m := range macros {
		assembled, err := Assemble(m.expansion)
		if err != nil {
			panic(err)
		}
		composite[m.ident] = assembled
		decomposite[m.expansion] = m.ident
	}
}
