# Slidechain

This is Slidechain,
a demonstration of a minimal Stellar sidechain.

Slidechain is configured with the Stellar account ID of a “custodian.”
The program monitors the Stellar network for payments to that account.
The program also operates a
(hosted)
TxVM blockchain.

When a Stellar payment to the custodian is seen,
a record is added to the `pegs` table in slidechain’s Sqlite3 database.
This record authorizes the custodian to sign a TxVM transaction issuing a corresponding amount and type of value on the TxVM sidechain.

When the TxVM value is retired
(via a special “unpeg” contract),
the custodian returns the funds on the Stellar chain to the account that pegged them.
