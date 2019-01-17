# Slidechain

This is Slidechain,
a demonstration of a minimal Stellar sidechain.

Slidechain is configured with the Stellar account ID of a “custodian.” The program monitors the Stellar network for payments to that account.
The program also operates a
(hosted)
TxVM blockchain.

When a Stellar payment to the custodian is seen,
a record is added to the `pegs` table in slidechain’s Sqlite3 database.
This record authorizes the custodian to sign a TxVM transaction issuing a corresponding amount and type of value on the TxVM sidechain.

When the TxVM value is retired
(via a special “unpeg” contract),
the custodian returns the funds on the Stellar chain to the account that pegged them.

## Demo

To run a demo of Slidechain end-to-end,
you must first build and run a `slidechaind` server instance.

From the `slidechain` directory:

```sh
$ go build ./cmd/slidechaind
$ ./slidechaind
```

This will create and run a new `slidechaind` instance,
generating a random keypair for the custodian account and funding the account with Stellar testnet funds.
`slidechaind` will log the custodian account ID:
we will need to use this for future commands.

Next,
we want to peg in funds from the Stellar network.

```sh
$ go build ./cmd/peg
$ ./peg -custodian [custodian account ID] -amount 100
```

This will peg-in 100 lumens to slidechain,
generating and funding a Stellar account from which to send the funds,
and also generating a txvm keypair to send the funds to on slidechain.
Both the Stellar account ID and the txvm keypair will be logged by `peg`.

When the import is processed,
`slidechaind` will log the txvm asset ID and the anchor:
we will need the anchor value to build and submit future transactions to slidechain.

Now,
you can build and submit any txvm transactions to manipulate the imported values.
For this demo,
we'll be immediately retiring the funds to peg them back out to the network.

You can create a new Stellar account using the
[Stellar Laboratory](https://www.stellar.org/laboratory/#account-creator?network=test)
to receive the funds,
or use the automatically-generated account from our `peg` command earlier.

```sh
$ go build ./cmd/export
$ ./export -destination [destination account ID] -amount 100 -anchor [import anchor] -prv [txvm prv key]
```

`slidechaind` will print logs that it is retiring the funds and building a peg-out transaction.
Using the logged transaction hash,
we can check that the transaction hit the network and the funds have been pegged out on
[Stellar Expert](stellar.expert/explorer/testnet/network-activity)
or using the
[Stellar Laboratory](https://www.stellar.org/laboratory/#explorer?network=test).
