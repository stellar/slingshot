package asm

import (
	"fmt"
	"unicode"
	"unicode/utf8"

	"github.com/chain/txvm/errors"
)

type scanner struct {
	// immutable state
	srcstr string // source

	// scanning state
	ch         rune    // current character
	offset     int     // character offset
	rdOffset   int     // reading offset (position after current character)
	lineOffset int     // current line offset
	errs       []error // scanner errors
}

func (s *scanner) initString(str string) {
	s.srcstr = str
	s.next()
}

type token int

const (
	tokIllegal token = iota
	tokNumber
	tokIdent
	tokHex
	tokString
	tokColon
	tokComma
	tokComment
	tokLeftBrace
	tokRightBrace
	tokLeftBracket
	tokRightBracket
	tokLabel
	tokJumpIf
	tokJump
	tokEOF
)

// next reads the next Unicode char into s.ch.
// s.ch < 0 means end-of-file.
//
func (s *scanner) next() {
	if s.rdOffset < len(s.srcstr) {
		s.offset = s.rdOffset
		if s.ch == '\n' {
			s.lineOffset = s.offset
		}
		r, w := rune(s.srcstr[s.rdOffset]), 1
		switch {
		case r == 0:
			s.error(s.offset, "illegal character NUL")
		case r >= utf8.RuneSelf:
			// not ASCII
			r, w = utf8.DecodeRuneInString(s.srcstr[s.rdOffset:])
			if r == utf8.RuneError && w == 1 {
				s.error(s.offset, "illegal UTF-8 encoding")
			}
		}
		s.rdOffset += w
		s.ch = r
	} else {
		s.offset = len(s.srcstr)
		if s.ch == '\n' {
			s.lineOffset = s.offset
		}
		s.ch = -1 // eof
	}
}

func isLetter(ch rune) bool {
	return 'a' <= ch && ch <= 'z' || 'A' <= ch && ch <= 'Z' || ch == '_' || ch >= utf8.RuneSelf && unicode.IsLetter(ch)
}

func isDigit(ch rune) bool {
	return '0' <= ch && ch <= '9' || ch >= utf8.RuneSelf && unicode.IsDigit(ch)
}

func (s *scanner) scanNumber() string {
	offs := s.offset
	if s.ch == '0' {
		s.next()
		if isDigit(s.ch) {
			s.error(offs, "illegal leading 0 in number")
		}
	} else {
		s.next()
		for isDigit(s.ch) {
			s.next()
		}
	}
	return s.srcstr[offs:s.offset]
}

func (s *scanner) scanIdentifier(offs int) string {
	for isLetter(s.ch) || isDigit(s.ch) {
		s.next()
	}
	return s.srcstr[offs:s.offset]
}

func (s *scanner) scanLabel() string {
	offs := s.offset - 1 // '$' already consumed
	lit := s.scanIdentifier(offs)
	if len(lit) == 0 {
		s.error(offs, "empty label $")
	}
	return lit
}

func (s *scanner) skipWhitespace() {
	for s.ch == ' ' || s.ch == '\t' || s.ch == '\n' || s.ch == '\r' {
		s.next()
	}
}

func (s *scanner) scanComment() string {
	offs := s.offset - 1 // '#' already consumed
	for s.ch != '\n' {
		s.next()
	}
	return s.srcstr[offs:s.offset]
}

func (s *scanner) scanString(delim rune) string {
	// `"` or `'` opening already consumed
	offs := s.offset - 1
	for {
		ch := s.ch
		if ch == '\n' || ch < 0 {
			s.error(offs, "string literal not terminated")
			break
		}
		s.next()
		if ch == delim {
			break
		}
		if ch == '\\' {
			s.scanEscape(delim)
		}
	}
	return s.srcstr[offs:s.offset]
}

// scanEscape parses an escape sequence where rune is the accepted
// escaped quote. In case of a syntax error, it stops at the offending
// character (without consuming it) and returns false. Otherwise
// it returns true.
func (s *scanner) scanEscape(quote rune) bool {
	offs := s.offset

	switch s.ch {
	case '\\', quote:
		s.next()
		return true
	default:
		msg := "unknown escape sequence"
		if s.ch < 0 {
			msg = "escape sequence not terminated"
		}
		s.error(offs, msg)
		return false
	}
}

func (s *scanner) scanHex(offs int) string {
	// 'x' opening already consumed
	quote := s.ch
	s.next()
	for {
		ch := s.ch
		if ch < 0 {
			s.error(offs, "hex literal not terminated")
			break
		}
		s.next()
		if ch == quote {
			break
		}
	}
	return s.srcstr[offs:s.offset]
}

func (s *scanner) scan() (pos int, tok token, lit string) {
	s.skipWhitespace()

	pos = s.offset
	lit = s.srcstr[s.offset:s.rdOffset]
	switch ch := s.ch; {
	case ('0' <= ch && ch <= '9') || ch == '-':
		tok, lit = tokNumber, s.scanNumber()
	default:
		s.next() // always make progress
		switch ch {
		case -1:
			tok = tokEOF
		case '{':
			tok = tokLeftBrace
		case '}':
			tok = tokRightBrace
		case ',':
			tok = tokComma
		case '[':
			tok = tokLeftBracket
		case ']':
			tok = tokRightBracket
		case '"', '\'':
			tok = tokString
			lit = s.scanString(ch)
		case '$':
			tok = tokLabel
			lit = s.scanLabel()
		case '#':
			tok = tokComment
			lit = s.scanComment()
		case ':':
			tok = tokColon
		case 'x':
			if s.ch == '\'' || s.ch == '"' {
				tok = tokHex
				lit = s.scanHex(pos)
			} else {
				tok = tokIdent
				lit = s.scanIdentifier(pos)
			}
		default:
			if isLetter(ch) {
				tok = tokIdent
				lit = s.scanIdentifier(pos)

				// handle symbolic jumps as separate tokens
				// from the `jump` and `jumpif` ops
				switch {
				case lit == "jump" && s.ch == ':':
					tok = tokJump
					lit = s.srcstr[pos:s.rdOffset]
					s.next()
				case lit == "jumpif" && s.ch == ':':
					tok = tokJumpIf
					lit = s.srcstr[pos:s.rdOffset]
					s.next()
				}
			} else {
				tok, lit = tokIllegal, string(ch)
			}
		}
	}
	return
}

func (s *scanner) error(offs int, msg string) {
	s.errs = append(s.errs, errors.Wrap(fmt.Errorf("txvm/asm: at %d, %s", offs, msg)))
}
