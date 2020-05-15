# Asset Import Protocol

* [Introduction](#introduction)
* [Use cases](#use-cases)
* [Alternative: atomic cross-chain swaps](#alternative-atomic-cross-chain-swaps)
* [Protocol overview](#protocol-overview)
* [Protocol architecture](#protocol-architecture)
* [Definitions](#definitions)
* [Specification](#specification)
* [Redundancy](#redundancy)
* [Censorship](#censorship)
* [Privacy](#privacy)

## Introduction

This is a protocol for importing and exporting assets on an external blockchain (such as Stellar) into the private ZkVM blockchain.

An asset is deposited to the custodian's address first, custodian detect the deposit and subsequently issues the mapped token. When a user needs to withdraw their native token, they first retire (in a specific way) their mapped token, which is detected by the custodian, who unlocks the corresponding native token in response.

<img width="600" alt="system overview" src="https://user-images.githubusercontent.com/698/82017863-60141600-9684-11ea-8d8a-5bb493785003.png" />

## Use cases

**(1) Public → ZkVM:** An asset is canonically defined and issued on a public
chain and needs to be moved to a private ZkVM ledger (e.g. to an exchange/custodian).

**(2) ZkVM → Public:** An asset is canonically defined and issued in a private ZkVM ledger
(e.g. a corporate stock) and needs to be "exported" to one of the public ledgers for trading. 

**(3) ZkVM → ZkVM:** Correspondent banking: entities hold accounts with each other and
do cryptogrpahic atomic transfers.

For completeness we will cover all three cases, but the most interesting is the first one: 
importing assets from a public chain to the private ledger.

## Alternative: atomic cross-chain swaps

An alternative design is for two assets on two ledgers to be traded within their respective chains, but with hash-locks providing assurance that trades either complete together, or both are reverted. In our scenario, the custodian would be issuing the mapped token and giving access to it simultaneously with getting native asset under control. Same for the withdrawal: user swaps mapped token with the native token, then issuer retires the mapped token (or maybe reuses it immediately with another deposit).

Issues with this approach:

**Atomic swaps are synchronous:** both parties must be well-connected and stay up-to-date to observe cancellation by a counterparty within a timeout window, so they can cancel their side of the trade. If they fail to do so, they will lose funds.

Atomic swaps require **two transactions** on each chain instead of one transaction on each chain, making them at least 2x slower on average than asynchronous mapping.

Atomic swaps require **special support from the wallet software**. But with asynchronous mapping it is possible to use ubiquitous "send to an address" UI as shown below.

Atomic swap introduce **additional state** that must be tracked outside of either ledger, which makes it more brittle and does not allow use of stateless secure computing platforms such as various HSMs, Intel SGX enclaves etc.

## Protocol overview

An asset therefore has two representations: **native token** and **mapped token**.

**Converter** is an entity that holds native tokens in **custody** and **issues** the corresponding mapped tokens.

Converter issues mapped tokens when a native asset is **deposited**,
and unlocks the deposited native token when the mapped token is **retired**.

### Preventing on-chain replays

When converter signs a transaction, it relies on external means to avoid double-spending. For instance, each transaction is tied to a **specific utxo id or account sequence number** preventing it from being published twice. So even if the request to the converter can be replayed, the produced signature will be only applicable to a unique transaction which itself cannot be replayed due to blockchain validation rules (enforced outside the converter).

### Preventing cross-chain replays

Transfers across chains involve events without a common anchor. For instance, if a deposit transaction is published on one chain, how do we make sure that the corresponding issuance of a mapped token is uniquely tied to that deposit and not duplicated?

We can use the assumption that ledgers are irreversible<sup>1</sup> and rely on **proofs of publication** and [**trackers**](#tracker), singleton data-carrying tokens that uniquely tie an event on one chain to an event on another.

<sup>1</sup> Chain reorganizations are handled with appropriately chosen confirmation depth as a function of money at stake, that is typically proportional to `log($$$)`.


## Protocol architecture

### Design considerations

We want to be able to use simple "send to address" interface
on the public ledger, regardless of whether the public ledger
is a [source](#source-ledger) or a [target](#target-ledger).

This affects the design in several ways:

1. **Full public ledger scan:** the entirety of the public ledger must be processed
   by the converter to detect all deposits. ZkVM ledger does not need to be fully scanned
   as deposits/withdrawals can be performed atomically with updates to a special-purpose
   singleton [tracker](#tracker) token, so that the converter needs to track changes to that token,
   ignoring all other transactions safely.
2. **Address mapping:** for each deposit we need to pre-declare
   pairs of [source](#source-ledger) and [target](#target-ledger) addresses.
   Given a set of such pairs, converter is able to know exactly which transactions
   on the public ledger are deposits and which are not. This allows us to guarantee
   that converter cannot skip some of the deposits.
3. **Asymmetry:** due to the need to perform the full ledger scan for the public ledger,
   the structure is not fully symmetric for different configurations. For instance,
   regardless of whether the ZkVM ledger is a source ledger or a target ledger,
   the [tracker](#tracker) must live on the ZkVM and not on the public ledger.
   Things are even more complex for public-to-public ledger conversions.


[Source ledger](#source-ledger)|[Target ledger](#target-ledger)|[Tracker](#tracker) location|Full chain scan?
-------------------------------|-------------------------------|----------------------------|-------------------------------
ZkVM                           |ZkVM                           |Source + Target             |No
Public                         |ZkVM                           |Target                      |Source chain only (deposits)
ZkVM                           |Public                         |Source                      |Target chain only (withdrawals)
Public                         |Public                         |Source + Target             |Both chains

### Public → ZkVM setting

**Source ledger:** public chain

**Target ledger:** sequence

**Tracker:** target (sequence)

**Deposits**

1. User tells the converter the address `T` on the [target ledger](#target-ledger) where they want to deposit mapped tokens. User does not tell the amount `V`.
2. Converter generates a corresponding deposit address `D` on the [source ledger](#source-ledger).
3. Converter updates the [target tracker](#tracker) with an added address mapping `D->T` with an expiration timestamp.
4. User waits till publication of their mapping in the [target tracker](#tracker).
5. User sends `V` to the target address `D` using a regular wallet on the [source ledger](#source-ledger).
6. Converter processes all transactions on the source ledger and detects the mapped deposits.
7. Converter signs a [target ledger](#target-ledger) transaction that has:
    1. `N` issuances for each of `N` detected deposits,
    2. an updated [target tracker](#tracker) state with:
        1. a new tip
        2. updated balances (utxo set recalculated or seqnum appropriately advanced)
        3. all expired mappings removed (we need to allow conversion of multiple sends to the same address).
8. Converter service publishes the transaction provided by the converter.

**Withdrawals**

1. User tells the enclave about the address `W` and value `V` on the [source ledger](#source-ledger) where they wish to withdraw their original token.
2. Converter generates a corresponding retirement address `R` on the [target ledger](#target-ledger).
3. Converter also generates a half-signed target-ledger transaction with two outputs:
    1. value `V` on retirement address `R`,
    2. an updated state of a [tracker](#tracker) with:
        1. counter incremented,
        2. the utxo/sequencenum/nonce reserved for [withdrawing](#withdrawal) a locked token on the [source ledger](#source-ledger) of amount `V` to address `W`.
        3. if retirement is non-destructive (returns to the pool of mapped tokens), [target ledger](#target-ledger)’s utxo identifier (`V->R`) added to the balance set in the [tracker](#tracker) state.
4. User verifies that the singleton state update respects `V->R` mapping.
5. User adds their `V` target-ledger funds to the transaction and signs it.
6. User publishes the transaction on the [target ledger](#target-ledger)
7. Once the tx is published, user submits the proof of publication ot the converter requesting a withdrawal on the [source ledger](#source-ledger).
8. Converter checks the proof of publication, looks up the reserved withdrawal details pre-recorded in the [tracker](#tracker) and deterministically produces a unique [withdrawal](#withdrawal) tx (it should not be signed before the publication happened).

Notes:

* Deposits in `pub->seq` setting are similar to withdrawals in `seq->pub` setting, and vice versa.
* Converter guarantees that the [tracker](#tracker) advances if and only if all new deposits are matched with corresponding issuances.
The integrity of the target ledger guarantees that the resulting transaction (that advances the tracking token and issues mapped tokens) is unique and issuances will not be duplicated.
* It is safe to replay stale proofs of publication as the withdrawal signatures correspond to a unique transaction. Moreover, that allows us to forget the assignments in the next batch of withdrawals, so that we do not need to perform "cleanup" when the withdrawals are actually published. Users would simply have to show the historical proof-of-publication to request completion of the withdrawal.



### ZkVM → Public setting

**Source ledger:** sequence

**Target ledger:** public chain

**Tracker:** source (sequence)

**Deposits**

1. User tells the converter about the address `T` and value `V` on the [target ledger](#target-ledger) where they wish to receive the mapped token.
2. Converter generates a corresponding deposit address `D` on the [source ledger](#source-ledger).
3. Converter also generates a half-signed source-ledger transaction with two outputs:
    1. value `V` on deposit address `D`,
    2. an updated state of a [tracker](#tracker) with:
        1. counter incremented,
        2. the utxo/sequencenum/nonce is reserved for [issuing](#issuance) a [mapped token](#mapped-token) of amount `V` to address `T`.
        3. deposit utxo identifier (`V->D`) added to the balance set in the [tracker](#tracker) state.
4. User verifies that the singleton state update respects `V->T` mapping.
5. User adds their `V` source-ledger funds to the transaction and signs it.
6. User publishes the transaction on the [source ledger](#source-ledger).
7. Once the tx is published, user submits the proof of publication ot the converter requesting an issuance on the [target ledger](#target-ledger).
8. Converter checks the proof of publication, looks up the reserved issuance details pre-recorded in the [tracker](#tracker) and deterministically produces a unique issuance tx (it should not be signed before the publication happened).

**Withdrawals**

1. User tells the converter the address `S` on the [source ledger](#source-ledger) where they want to withdraw mapped tokens. User does not tell the amount `V`.
2. Converter generates a corresponding retirement address `R` on the [target ledger](#target-ledger).
3. Converter updates the [tracker](#tracker) with an added address mapping `R->S` with an expiration timestamp.
4. User waits till publication of their mapping in the [tracker](#tracker).
5. User sends `V` to the target retirement address `R` using a regular wallet on the [target ledger](#target-ledger).
6. Converter processes all transactions on the target ledger and detects the mapped withdrawals.
7. Converter signs a [source ledger](#source-ledger) transaction that has:
    1. `N` detected withdrawals,
    2. an updated [tracker](#tracker) state with:
        1. a new tip
        2. updated balances (utxo set recalculated or seqnum appropriately advanced)
        3. all expired mappings removed (we need to allow conversion of multiple sends to the same address).
8. Converter service publishes the transaction provided by the converter.

Notes:

* Withdrawals in `seq->pub` setting are similar to deposits in `pub->seq` setting, and vice versa.
* Issuances are logically chained in the [tracker](#tracker), so cannot be skipped selectively.
* Deposits must go through a special "peg to public" API where it orchestrates co-signing with converter.


### ZkVM → ZkVM setting

**Source ledger:** sequence

**Target ledger:** sequence

**Tracker:** one on source, one on target

**Deposits**

1. User tells the converter about the address `T` and value `V` on the [target ledger](#target-ledger) where they wish to receive the mapped token.
2. Converter generates a corresponding deposit address `D` on the [source ledger](#source-ledger).
3. Converter also generates a half-signed source-ledger transaction with two outputs:
    1. value `V` on deposit address `D`,
    2. an updated state of a [source tracker](#tracker) with:
        1. counter incremented,
        2. the utxo/sequencenum/nonce is reserved for [issuing](#issuance) a [mapped token](#mapped-token) of amount `V` to address `T`.
        3. deposit utxo identifier (`V->D`) added to the balance set in the [tracker](#tracker) state.
4. User verifies that the singleton state update respects `V->T` mapping.
5. User adds their `V` source-ledger funds to the transaction and signs it.
6. User publishes the transaction on the [source ledger](#source-ledger).
7. Once the tx is published, user submits the proof of publication ot the converter requesting an issuance on the [target ledger](#target-ledger).
8. Converter checks the proof of publication, looks up the reserved issuance details pre-recorded in the [source tracker](#tracker) and deterministically produces a unique issuance tx (it should not be signed before the publication happened).


**Withdrawals**

1. User tells the converter about the address `W` and value `V` on the [source ledger](#source-ledger) where they wish to withdraw their original token.
2. Converter generates a corresponding retirement address `R` on the [target ledger](#target-ledger).
3. Converter also generates a half-signed target-ledger transaction with two outputs:
    1. value `V` on a retirement address `R`,
    2. an updated state of a [target tracker](#tracker) with:
        1. counter incremented,
        2. the utxo/sequencenum/nonce reserved for [withdrawing](#withdrawal) a locked token on the [source ledger](#source-ledger) of amount `V` to address `W`.
        3. if retirement is non-destructive (returns to the pool of mapped tokens), [target ledger](#target-ledger)’s utxo identifier (`V->R`) added to the balance set in the [tracker](#tracker) state.
4. User verifies that the singleton state update respects `V->R` mapping.
5. User adds their `V` target-ledger funds to the transaction and signs it.
6. User publishes the transaction on the [target ledger](#target-ledger)
7. Once the tx is published, user submits the proof of publication ot the converter requesting a withdrawal on the [source ledger](#source-ledger).
8. Converter checks the proof of publication, looks up the reserved withdrawal details pre-recorded in the [target tracker](#tracker) and deterministically produces a unique [withdrawal](#withdrawal) tx (it should not be signed before the publication happened).


### Public → Public setting

**Source ledger:** public chain

**Target ledger:** public chain

**Tracker:** on both chains

**Deposits**

1. User tells the converter the address `T` on the [target ledger](#target-ledger) where they want to deposit mapped tokens. User does not tell the amount `V`.
2. Converter generates a corresponding deposit address `D` on the [source ledger](#source-ledger).
3. Converter updates the [target tracker](#tracker) with an added address mapping `D->T` with an expiration timestamp.
4. User waits till publication of their mapping in the [target tracker](#tracker).
5. User sends `V` to the source deposit address `D` using a regular wallet on the [source ledger](#source-ledger).
6. Converter processes all transactions on the source ledger and detects the mapped deposit.
7. Converter signs a [target ledger](#target-ledger) transaction that has:
    1. `N` detected deposits,
    2. an updated [target tracker](#tracker) state with:
        1. a new tip
        2. updated balances (utxo set recalculated or seqnum appropriately advanced)
        3. all expired mappings removed (we need to allow conversion of multiple sends to the same address).
8. Converter service publishes the transaction provided by the converter.


**Withdrawals**

1. User tells the converter the address `S` on the [source ledger](#source-ledger) where they want to withdraw mapped tokens. User does not tell the amount `V`.
2. Converter generates a corresponding retirement address `R` on the [target ledger](#target-ledger).
3. Converter updates the [target tracker](#tracker) with an added address mapping `R->S` with an expiration timestamp.
4. User waits till publication of their mapping in the [tracker](#tracker).
5. User sends `V` to the target retirement address `R` using a regular wallet on the [target ledger](#target-ledger).
6. Converter processes all transactions on the target ledger and detects the mapped withdrawal.
7. Converter signs a [source ledger](#source-ledger) transaction that has:
    1. `N` detected withdrawals,
    2. an updated [source tracker](#tracker) state with:
        1. a new tip
        2. updated balances (utxo set recalculated or seqnum appropriately advanced)
        3. all expired mappings removed (we need to allow conversion of multiple sends to the same address).
8. Converter service publishes the transaction provided by the converter.






### Tracker state

[Tracker](#tracker) is a token implementing an irreversible state machine with the following structure:

Field               | Type              | Description
--------------------|-------------------|-----------------------
`counter`           | `u64`             | Linearly grows with each update, used to derive converter-controlled addresses.
`external_tip`      | `hash256`         | 32-byte hash of the block of the other chain which is already processed.
`address_map`       | `AddressMap`      | [Address map](#address-map) in a form of a radix tree.
`balances`          | `Balances`        | List of [balances](#balances) on the other chain in a form of a merkle root.
`withdrawals`       | `Vec<Withdrawal>` | List of reserved [withdrawals](#reserved-withdrawals) from the balances.


When one chain is fully scanned:

1. Tip of the other chain.
2. Available balance (utxo set OR total balance and current sequence number).
3. Withdrawals assignment (utxo+amount OR sequencenum+amount).

When one chain is not fully scanned and contains its own tracking token:

1. utxo id / account seqnum of the other tracking token.
2. Available balance (utxo set OR total balance and current sequence number).
3. Withdrawals assignment (utxo+amount OR sequencenum+amount).


### Address map

In order to enable simple pay-to-address interface, user needs to pre-register a pair `A:B`
to transfer value on one chain to `A` in order to receive a corresponding token on the other chain
on the address `B`.

To make the map scalable, it is organized in a radix tree; for each transfer in a block,
converter infrastructure prepares proofs of inclusion or non-inclusion for the corresponding addresses.

The tree is keyed by the first address (for deposits or retirements),
and the value is the second address (for issuance or withdrawals, respectively), plus the expiration
Unix timestamp in seconds (u64).

    hash256("Key", address1) -> (address2, expiration_sec)

The merkle root is computed as such:

    /// Leaf hash:
    H({item}) := hash256("Leaf", lenprefixed(item.address1) || lenprefixed(item.address2) || expiration_sec)

    /// Inner hash:
    H(items[0:n]) := hash256("Inner", H(items[0:k]) || H(items[k:n]))

TBD: add encryption for the values.

Length prefixing:

    lenprefixed(string) := u64le(len(string)) || string

Hash:

    hash256(l,x) = hmac-sha512(l, x)[0:32]

Proof of membership:

    TBD.

Proof of non-membership:

    TBD.

Batch proof:

    TBD: enumerate items of interest and necessary neighbouring elements to reconstruct the root.


### Balances

The "wallet" of the converter custodian.

* **UTXO-based** blockchain: a list of `(txid, output_index, value)` (bitcoin) or `(output_id)` (txvm).
* **Account-based** blockchain: a list of `(account_id, sequence_number, value)` (ethereum, stellar).

TBD: how to hash the balances, so it's easy to remove from the start and add to the end.

The set of balances represents the state of the wallet assuming all
[reserved withdrawals](#reserved-withdrawals) are processed.
    

### Reserved withdrawals

The list of the same tuples as in [balances](#balances), in FIFO order.
These are guaranteed to be processed in order.





## Definitions

#### Person

A decision maker that owns [tokens](#token).

#### Converter

A machine that implements a custodian (typically a cluster of physical instances): that processes [deposits](#deposit) and [withdrawals](#withdrawal). On par with [people](#person) owns [tokens](#token).

#### Token

A unit of value on some [ledger](#ledger).

#### Ledger

A record of allocations of [tokens](#token) among [people](#person). A ledger allows [people](#person) and [converter](#converter) to transfer only the tokens they own.

#### Source token

The unit of value defined in the [source ledger](#source-ledger), issued outside the scope of this protocol.

#### Mapped token

The unit of value defined in the [target ledger](#target-ledger), issued by the [converter](#converter) per rules of the present protocol.

#### Source ledger

The [ledger](#ledger) where the [source tokens](#source-token) exist.

#### Target ledger

The [ledger](#ledger) where the [mapped tokens](#mapped-token) exist.

#### Deposit

Transfer of a [source token](#source-token) from a [person](#person) to the [converter](#converter) with the intent to receive an [issued](#issuance) [mapped token](#mapped-token) on the [target ledger](#target-ledger).

#### Withdrawal

Transfer of a [source token](#source-token) from the [converter](#converter) to a [person](#person) tied with [retirement](#retirement) of a [mapped token](#mapped-token) on the [target ledger](#target-ledger).

#### Issuance

Transfer of a [mapped token](#mapped-token) from the [converter](#converter) to a [person](#person) that corresponds to a [deposit](#deposit) of a [source token](#source-token).

Issuance may be implemented as a formal issuance (like in TxVM), or as a transfer from a pool of previously created tokens. We leave this as an implementation detail outside the scope of this protocol.

#### Retirement

Transfer of a [mapped token](#mapped-token) from a [person](#person) to the [converter](#converter) that corresponds to a [withdrawal](#withdrawal) of a [source token](#source-token).

Retirement may be implemented as a formal destruction (like in TxVM), or as a transfer into a pool of [converter](#converter)-controlled tokens. We leave this as an implementation detail outside the scope of this protocol.

#### Tracker

A singleton token with a pre-determined flavor ID. At each state, the token stores a unique hash of its [state](#tracker-state).












## Setup

WIP: expand on this:

1. Converter exclusively owns the secret keys used for the source token deposits and withdrawals and mapped tokens issuance.
2. Converter issues a singleton token on a target ledger acting as a **state record** which tracks the state of all deposits and pending withdrawals (acting like a wallet DB controlled by the converter).


## Specification

TBD: in order to avoid full scan of the source chain, we can probably use another singleton "tracker" token on the src chain, that keeps track of pending deposits and the current height of the secondary chain. But this forces users to co-sign deposits with the tracker update, which makes deposits detectable and requires potentially non-standard software to sign such transactions (instead of simply sending to an address).

TBD: outline of the state struct and state transitions

TBD: how to detect deposits? E.g. in Bitcoin there are 3 mechanisms:

1. `base58`: Base58 address or BIP21 URI without amount (e.g. a static QR code).
2. `bip-21`: BIP-21 URI with amount (e.g. a dynamic QR code generated due to user's request).
3. `bip-70`: BIP-70 URI with arbitrary set of outputs (script+amount tuples).

(1) `base58`: we cannot use one-time addresses, so we simply detect deposits to the single static address.

(2) `bip-21`: converter uses amount as a seed to derive a key from `xpub`, so deposits are linkable only for identical amounts. As a variant, we can generate an additional random amount of satoshis up to 0.01% of the amount requested to add some entropy. The key is unique as long as the deposit amount is not repeated to the same converter instance.

(3) `bip-70`: same derivation as (2), but converter generates two outputs with random split of the precise amount among them. `OP_RETURN` output with higher-entropy salt is not used to minimize identification of deposits. Although if UTXO pressure is considered pretty bad, `OP_RETURN` is a working alternative.

TBD: how to detect the destination address on the other chain?

`base58` just does not work. `bip-21` also does not work. `bip-70` allows specifying destination address via `op_return`.

### Radix tree for address mappings

TBD: Need aggregated proof of membership and non-membership for a contiguous set of transactions in a given range of public ledger blocks. Converter only verifies that all spendings are correctly processed as deposits/withdrawals or correctly skipped as non-members of the map. Untrusted environment prepares the proofs from the actual data set.




## Redundancy

Converter must be a replicated cluster of physical devices, so that each individual device can perform operations on behalf of the cluster as a single logical entity. This means, that the root key will be defined not by a CPU, but by a separately generated secret which is replicated to a number of CPUs.

It is possible to perform this operation in a way that's auditable later: one converter generates a secret, annotates it with the list of all CPU-bound public keys of the other devices, and returns the signed collected of ciphertexts for itself and other devices. The resulting bundle is auditable at a later time via Remote Attestation: if each per-CPU public key is attested to be coming from the same trusted converter software+hardware, then the shared key could not have been escrowed.

Cluster can be healed by setting up a fresh shared key in the same manner on a different set of devices. Then, each time users deposit funds with the converter-controlled keys, they will be using the latest key, ensuring that they do not keep funds for long time with a decaying cluster.

The above is the most paranoid setup when you want to _avoid any way_ to manipulate the deposited funds. In practice, it may be acceptable to have a 2-of-3 or 3-of-5 threshold encryption of the shared key, so that the honest majority of admins can re-encrypt the shared key to the new cluster (after remote-attesting it first, of course) in case that's needed.

## Censorship

Main way to prevent censorship is via Confidential Assets (for on-chain transactions) and end-to-end encrypted and anonymous transport between the user and the converter.

Note that all operations are carefully tied to updates in a singleton state tracking object, to ensure consistency of the system. This also means, that the censorship via converter infrastructure is all-or-nothing: either converter is disconnected entirely and no withdrawals are possible, or the pending withdrawals must be processed. The end-to-end encrypted requests to the converter are opaque, making different private operations indistinguishable to the infrastructure around it. 

TBD: think how to unlink withdrawal "retirements" from the state tracker. At the very minimum, all withdrawal attempts must be indistiniguishable among each other, even if they are distinguishable from non-withdrawal transactions.

## Privacy

#### Secure transport

Communication with the converter is going through an end-to-end encrypted channel, so that surrounding environment is handling opaque (sealed+signed) data on behalf of converter to service its uninterrupted operation. The server hosting the converter runs the Tor hidden service and the SDK can connect via Tor to make sure we cannot link requests from the same host.

#### Selective disclosure

The tracker state is a merkle-ish structure, so when the user needs to verify that a certain fact is committed, that could be proven directly to the user w/o leaking facts relevant to the other users.

The tracker's mapping of addresses (e.g. deposit-target pair `D:T`) is actually encrypted as `Enc(D):Enc(T)` under the converter's key. So that the surrounding service is able to construct merkle-path-proofs for these entries, but w/o visibility into which addresses are actually used.

#### Linkability

Deposits are unlinkable via one-time addresses. Withdrawals linked atomically with the record update, but amounts/contents can be encrypted. Only facts of withdrawals are identified.

Deposits/withdrawals processed in batches with pre-programmed batch size to enforce a window for anonymity set. E.g. all deposits are guaranteed to be grouped over at least a 1 minute interval. We may also support fast and slow modes for dev and production respectively. So that in development there minimal delay to be able to test the grouping in principle, but w/o strong anonymity requirement. In production there would be 1 minute delay. As userbase grows, the anonymity set would naturally expand, but for low tx rates, any reasonable delay would not add much to privacy.


