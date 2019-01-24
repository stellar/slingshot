# Slidechain

This is Slidechain,
a demonstration of a minimal
[Stellar](https://stellar.org/)
sidechain.
Slidechain allows you to _peg_ funds from the Stellar testnet,
_import_ then to a _sidechain_,
and later _export_ them back to Stellar.

Pegged funds are immobilized on the originating network while the imported funds exist on the sidechain.
Typically,
the sidechain permits special operations that aren’t possible or aren’t permitted on the originating network.
A good analogy:
converting your cash into casino chips while you’re gambling,
then back to cash when you’re done.

In Slidechain,
the sidechain is based on TxVM,
which is designed to permit safe,
general-purpose smart contracts and flexible token issuance.
Learn more about TxVM at
[its GitHub repo](https://github.com/chain/txvm).

The pegging mechanism for Slidechain depends on a _trusted custodian_.
It is described in detail
[here](Pegging.md).

You can run the Slidechain demo.
Instructions are
[here](Running.md).





sidechain where the values can be manipulated and pegged back out to the Stellar network.

Slidechain is configured with the Stellar account ID of a “custodian.” The program monitors the Stellar network for payments to that account.
The program also operates a
(hosted)
TxVM blockchain.

A peg-in to slidechain consists of a Stellar payment to the custodian account with the public key of the TxVM-side recipient in the transaction's `memo` field.
When a Stellar peg-in transaction to the custodian is seen,
a record is added to the `pegs` table in slidechain’s Sqlite3 database.
This record authorizes the custodian to sign a TxVM transaction issuing a corresponding amount and type of value on the TxVM sidechain to the recipient.

Values are retired from the sidechain by submitting a TxVM `retire` transaction,
specifying in the transaction's reference data the asset and destination of the pegged-out funds.
The custodian will retire the TxVM-side assets and issue a Stellar transaction pegging out the funds on the Stellar chain to the specified destination account.
