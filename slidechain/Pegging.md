# The Slidechain pegging mechanism

This document describes the mechanism by which Stellar funds are _pegged_ to values on a
[TxVM](https://github.com/chain/txvm/)
sidechain.

The mechanism described here depends on a _trusted custodian_.
There are other pegging techniques not discussed here.
You can read more about them
[here](https://medium.com/blockchain-musings/pegged-sidechains-cafe1d8c7023),
among other places.

## Terminology

Some funds exist on a _main chain_.

These may be _pegged in_.
This means the funds are immobilized and may not be used in any way on the main chain until they are _pegged out_.

Once funds are _pegged in_,
they are _imported_ to the sidechain.
Importing means issuing new value on the sidechain that corresponds 1:1 with the pegged-in funds.

Imported funds may subsequently be _exported_.
Exported funds are permanently retired from the sidechain.

Once funds have been exported from the sidechain,
the corresponding funds on the main chain may be _pegged out_,
or released from immobilization.

## Requirements

The pegging mechanism must provide security by guaranteeing that:

- all funds that have been pegged in can be imported;
- all funds that have been imported can be exported;
  and
- all funds that have been exported can be pegged out.

Furthermore,
it must guarantee that no funds can be pegged in,
imported,
exported,
or pegged out more than once.

## The mechanism

In Slidechain’s trusted-custodian model,
an entity called a custodian controls an account on the Stellar network
(the “custodian account”)
and a keypair on the TxVM sidechain.
Participants trust the custodian to perform the operations described in this document promptly and faithfully.

### Pegging in

Pegging in Stellar funds for import to TxVM requires two steps:

1. Create a _uniqueness token_
   (a contract)
   on the TxVM chain that encodes the arguments to be used later in the import step:
   namely,
   the amount and Stellar asset code of the pegged value,
   plus the pubkey of the intended recipient of the imported funds.
2. Publish a Stellar transaction that pays peg-in funds to the custodian’s account,
   and that includes the uniqueness token’s ID in its Memo field.

The uniqueness token will be consumed in the import step.
It exists to ensure the import for this specific peg-in can happen only once.
It contains a zero-value
(created with TxVM’s
[nonce](https://github.com/chain/txvm/blob/main/specifications/txvm.md#nonce)
instruction)
to guarantee uniqueness.

The uniqueness token refuses to be called by anything other than the import-issuance contract,
described below.
Calling the program in the uniqueness token causes it first to check that this is the case
(via
[caller](https://github.com/chain/txvm/blob/main/specifications/txvm.md#caller)),
then to move the contents of its stack — its zero-value,
its amount,
its Stellar asset code,
and its recipient pubkey — to the argument stack,
where it will be used by the import-issuance contract.

The `caller` check prevents others besides the custodian from consuming the uniqueness token prematurely in some other context,
which would prevent import from working and result in the loss of pegged-in funds.

### Importing

The custodian monitors the Stellar network,
looking for payments to the custodian account that match the other criteria of a peg-in transaction.
When it finds one,
it uses its Memo field as a lookup key to correlate the peg-in transaction with the pre-peg-in uniqueness token.
The custodian then submits an import transaction to TxVM that performs the following steps:

1. [Inputs](https://github.com/chain/txvm/blob/main/specifications/txvm.md#input)
   the uniqueness token and
   [puts](https://github.com/chain/txvm/blob/main/specifications/txvm.md#put)
   it on the argument stack.
2. Creates an instance of a special _import-issuance contract_
   (described below)
   and
   [calls](https://github.com/chain/txvm/blob/main/specifications/txvm.md#call)
   it.
   This produces on the argument stack:
   - a new TxVM value with an amount equal to,
     and an asset type computed from,
     the pegged-in Stellar funds;
   - a signature-check program that will have to be satisfied
     (ensuring none but the custodian can consume the uniqueness token or issue new value);
   - the recipient pubkey.
3. Pays the new value to the recipient
   (e.g.
   using
   [the standard pay-to-multisig contract](https://github.com/chain/txvm/blob/d4707728bddcbe7acb5722f2718b3d419006595f/protocol/txbuilder/standard/output.go#L29-L31)).
4. Supplies the custodian’s signature to the signature-check program.

The import-issuance contract takes the uniqueness token as an argument and calls it,
producing the amount,
Stellar asset code,
recipient pubkey,
and zero-value that were encoded in it.
The zero-value,
amount,
and Stellar asset code are used as arguments to the
[issue](https://github.com/chain/txvm/blob/main/specifications/txvm.md#issue)
instruction,
producing a new TxVM value.
Its asset type is uniquely determined by the Stellar asset code and the
[seed](https://github.com/chain/txvm/blob/main/specifications/txvm.md#contract-seed)
of the import-issuance contract.
The issued value and recipient pubkey are the results and are moved to the argument stack,
together with a signature-checking contract that requires the custodian’s signature.

### Exporting

Exporting funds from TxVM for peg-out to Stellar requires three steps:

1. Create a new _temporary account_ in Stellar,
   funded with 2 lumens;
2. Change the temporary account’s
   [options](https://www.stellar.org/developers/guides/concepts/list-of-operations.html#set-options)
   as described below;
3. [Retire](https://github.com/chain/txvm/blob/main/specifications/txvm.md#retire)
   some imported funds in a transaction where the `retire` instruction is immediately followed by a
   [log](https://github.com/chain/txvm/blob/main/specifications/txvm.md#log)
   of this JSON string:
   `{"asset":ASSET,"temp":TEMP,"seqnum":SEQNUM,"exporter":EXPORTER}`,
   where
   - ASSET is the Stellar asset code
     (as base64-encoded XDR)
     of the funds to peg out;
   - TEMP is the temporary account created in step 1;
   - SEQNUM is the sequence number of the temporary account;
   - EXPORTER is the creator of the temporary account and the intended recipient of the peg-out funds.

The temporary account will be closed
(merged back to the exporter’s account)
in the peg-out step.
It exists to ensure the peg-out step for this particular export can happen only once.
The 2 lumens it contains are enough to cover the temp account’s
[minimum balance](https://www.stellar.org/developers/guides/concepts/fees.html#minimum-account-balance)
plus the costs of the SetOptions and the peg-out transactions,
both described below.
Any excess is paid back to the recipient of the peg-out when the temp account is merged.

After the temporary account is created,
another Stellar transaction must set its options:
- the weight of its master key must be set to zero;
- the signing threshold must be set to 2;
- two signers must be added:
  - the custodian’s public key;
    and
  - a preauth transaction that merges the temp account and pays the peg-out funds from the custodian,
    both with the peg-out recipient as the destination.

(This `SetOptions` step must follow the temp-account-creation step separately since creating the preauth transaction requires knowing the temp account’s sequence number.)

With this
[multisig](https://www.stellar.org/developers/guides/concepts/multi-sig.html)
setup,
the only thing it is possible to do with the temp account is to merge it,
and the only one who can do that is the custodian.

### Pegging out

The custodian monitors the TxVM blockchain,
looking for export transactions.
When it finds one,
it parses the information in the JSON string and verifies that the TxVM asset ID of the value being retired corresponds to the given Stellar asset code.
It then publishes the preauthorized transaction described above that closes
(merges)
the temp account and pays the pegged-out funds to the recipient.

Note:
it is possible for the TxVM export transaction to succeed and the preauthorized peg-out transaction to fail
(e.g.
if the destination account no longer exists or does not have the correct
[trustline](https://www.stellar.org/developers/guides/concepts/assets.html#trustlines)).
This is a loss-of-funds scenario that requires further refinement for improved safety.
For example,
the export transaction could lock the exported funds in a smart contract that can either
(a)
`retire` those funds or
(b)
repay them to the exporter,
at the custodian’s discretion,
depending on whether the peg-out transaction succeeds.
