/*
Package bc defines basic blockchain data structures: transactions,
blockheaders, and blocks.

The transaction structure defined here is the _output_ of a TxVM
transaction program. It's created with NewTx, which runs that program
to populate the data structure.

This package also defines a 32-byte Hash type as a protocol buffer
message.
*/
package bc
