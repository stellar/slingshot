/*

Package txvm implements Chain Protocol transactions.

A transaction is a program (as a bytecode string) that is executed by
the stack-based txvm virtual machine.

Central to the operation of the virtual machine are two concepts:
"values" and "contracts."

A value is an amount of some asset type. The rules of the virtual
machine limit the ways in which values may be manipulated, ensuring
that no unbalanced transaction can ever be a valid txvm program.

A contract is a txvm subroutine plus some associated state, in the
form of a stack. When a contract runs, it manipulates the items on its
stack. It may suspend execution with the yield instruction, with
processing to continue later in the same transaction, or with the
output instruction, with processing to continue in a later transaction
via the input instruction.

During execution, value-manipulating structures are produced as
side-effects:

 - Issuances: new units of a caller-defined asset type are created.
 - Outputs: units of an asset are "locked" by specifying the
   conditions needed to unlock and spend them. An output is simply a
   contract that has suspended itself with the output instruction and
   that contains some value on its stack.
 - Inputs: previously locked value is unlocked by satisfying an
   output's conditions.
 - Retirements: units of an asset type are permanently removed from
   circulation.

Significant events during processing, including the creation of the
above-named structures, cause relevant entries to accumulate in the
virtual machine's "transaction log." The log may be inspected to
discover the transaction's effects (especially to find the IDs of
inputs and outputs for removing from the utxo set and adding to it,
respectively). The log is hashed to get the overall transaction ID.

*/
package txvm
