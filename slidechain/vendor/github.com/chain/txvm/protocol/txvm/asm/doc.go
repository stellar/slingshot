/*

Package asm provides an assembler and disassembler for txvm bytecode.

In the txvm assembly language implemented by this package, each opcode
in the txvm instruction set is represented by its all-lowercase name
(e.g. "swap" and "add"). Literals are represented as follows:

 - integers: 123, -72
 - hex strings: x'ec7a' or x"ec7a"
 - readable strings: 'foo' or "foo" (with \ escaping)
 - program strings: [...assembly code...]
 - tuples: {'V', 20, x'ec7a220e...', x'b773ae91...'}

An identifier preceded with $ is a symbolic jump target. A conditional
jump to target $foo can be written as jumpif:$foo. An unconditional
jump to target $foo can be written as jump:$foo.

The assembler also supports a handful of built-in convenience macros
that expand to longer sequences of instructions:

 - bool: not not (convert any data value to a 0 or 1)
 - swap: 1 roll (swap top two items on the stack)
 - sub: neg add (subtract integers)
 - splitzero: 0 split
 - le: gt not (less than or equal)
 - ge: swap le (greater than or equal)
 - lt: swap gt (less than)

Whitespace between tokens in assembler input is insignificant.
Comments are introduced by # and continue to the end of line.

*/
package asm
