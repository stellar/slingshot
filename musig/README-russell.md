# Multi-message signatures: Engineering design doc

This is a signature scheme for signing messages. 
The first iteration describes the protocol for signing a single message with one public key. 
The public key can be created from a single party's private key, 
or it can be created from the aggregation of multiple public keys. 

In future iterations, we can consider signing with public keys that are nested aggregations of public keys, 
and signing multiple messages in a way that is safe against Russell's attack.

## Definitions

### Scalar

A _scalar_ is an integer modulo [Ristretto group](https://ristretto.group) order 
`|G| = 2^252 + 27742317777372353535851937790883648493`.

Scalars are encoded as 32-byte strings using little-endian convention.

Every scalar is required to be in a canonical (reduced) form.

### Point

A _point_ is an element in the [Ristretto group](https://ristretto.group).

Points are encoded as _compressed Ristretto points_ (32-byte strings).


### Base point

Ristretto base point in compressed form:

```
B = e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76
```

### Signature

A signature is comprised of a scalar `s`, and a RistrettoPoint `R`. 
In the simple Schnorr signature case, `s` represents the Schnorr signature scalar and `R` represents the nonce commitment. 
In the Musig signature case, `s` represents the sum of the Schnorr signature scalars of each party, or `s = sum_i (s_i)`. 
`R` represents the sum of the nonce commitments of each party, or `R = sum_i (R_i)`. 

Functions:
- `Signature::verify(...)`: For more detail, see the [verification](#verifying) section.

## Operations

### Signing

There are several paths to signing:
1. Make a Schnorr signature with one public key (derived from one private key).
    Function: `Signature::sign_single(...)`

    Input: 
    - transcript: `&mut Transcript` - a transcript to which the message to be signed has already been committed.
    - privkey: `Scalar`

    Operation:
    - Clone the transcript state, mix it with the privkey and system-provided RNG to generate the nonce `r`. 
    This makes the nonce uniquely bound to a message and private key, and also makes it non-deterministic to prevent "rowhammer" attacks.
    - Use the nonce to create a nonce commitment `R = r * G`
    - Make `c = H(X, R, m)`. Because `m` has already been fed into the transcript externally, 
    we do this by committing `X = privkey * G` to the transcript with label "X", 
    committing `R` to the transcript with label "R", and getting the challenge scalar `c` with label "c".
    - Make `s = r + c * x` where `x = privkey`

    Output:
    - Signature { s, R }

2. Make a Schnorr signature with one aggregated key (`Multikey`), derived from multiple public keys.
    - Create an aggregated pubkey. For more information see the [key aggregation](#key-aggregation) section.

    For each party that is taking part in the signing:
    - Call `Party::new(transcript, privkey, multikey, pubkeys)`.
    - Get back `PartyAwaitingPrecommitments` and a `NoncePrecommitment`.
    - Share your `NoncePrecommitment`, and receive other parties' `NoncePrecommitment`s. 

    - Call `receive_precommitments(precommitments)` on your `PartyAwaitingPrecommitments` state, 
    inputting a vector of all parties' precommitments.
    - Get back `PartyAwaitingCommitments` and a `NonceCommitment`.
    - Share your `NonceCommitment`, and receive other parties' `NonceCommitment`s.

    - Call `receive_commitments(commitments)` on your `PartyAwaitingCommitments` state, 
    inputting a vector of all parties' commitments.
    - Get back `PartyAwaitingShares` and a `Share`.
    - Share your `Share`, and receive other parties' `Share`s.

    - Call `receive_shares(share)` on your `PartyAwaitingShares`.
    - Get back `Signature`. You are done!

3. Make a Schnorr signature with multiple public keys and multiple mesesages, that is Russell's attack resistant.
    For each party that is taking part in the signing:
    - Call `Party::new(transcript, privkey, message)`.
    - Get back `KeyMessage` and `PartyAwaitingKeyMessages`
    - Share your `KeyMessage`, and receive other parties' `KeyMessage`s.
    // TODO: can we merge this step with the next step, to save one round?

    - Call `receive_keymessages(keymessages)` on your `PartyAwaitingKeyMessages` state, 
    inputting a vector of all parties' keymessage pairs.
    - Get back `PartyAwaitingPrecommitments` and a `NoncePrecommitment`.
    - Share your `NoncePrecommitment`, and receive other parties' `NoncePrecommitment`s. 

    - Call `receive_precommitments(precommitments)` on your `PartyAwaitingPrecommitments` state, 
    inputting a vector of all parties' precommitments.
    - Get back `PartyAwaitingCommitments` and a `NonceCommitment`.
    - Share your `NonceCommitment`, and receive other parties' `NonceCommitment`s.

    - Call `receive_commitments(commitments)` on your `PartyAwaitingCommitments` state, 
    inputting a vector of all parties' commitments.
    - Get back `PartyAwaitingShares` and a `Share`.
    - Share your `Share`, and receive other parties' `Share`s.

    - Call `receive_shares(share)` on your `PartyAwaitingShares`.
    - Get back `Signature`. You are done!


### Verifying

Signature verification happens in the `Signature::verify(...)` function.

Input: 
- `&self`
- transcript: `&mut Transcript` - a transcript to which the signed message has already been committed.
  // TODO: does this still have to be true? The protocol could just commit the message directly...
- S: `Vec<(VerificationKey, Message)>`

Operation:

- Make `c_i = H(R, <S>, i)` for each party `i`. 
  Commit `R` with the label "R", and `<S>` as each of the pairs in input `S` with label "S", and `i` with label "i". 
- Decompress verification keys `X_i` for all `i`. If this fails, return `Err(VMError::InvalidPoint)`.
- Make `sum_i(c_i, X_i)` and add it to `R`.
- Check if it is equal to `s * G`. `G` is the [base point](#base-point).

Output:
- `Ok(())` if verification succeeds, or `Err(VMError)` if the verification or point decompression fail.

## Protocol for party state transitions

We create a different struct for each party step in the protocol, to represent the state and state transition. 
This allows us to use the Rust type system to enforce correct state transitions, 
so we have a guarantee that the protocol was followed in the correct order.

Party state transitions overview:
```
Party{}
  ↓
.new(transcript, privkey, message) → KeyMessage(VerificationKey, Message)
  ↓
PartyAwaitingKeyMessages{transcript, privkey, message}
  ↓
.receive_keymessages(self, Vec<keymessage>) → NoncePrecommitment([u8; 32])
  ↓
PartyAwaitingPrecommitments{transcript, privkey, nonce, noncecommitment, Vec<Counterparty>}
  ↓
.receive_precommitments(self, Vec<precommitment>) → NonceCommitment(RistrettoPoint)
  ↓
PartyAwaitingCommitments{transcript, privkey, nonce, Vec<CounterpartyPrecommitted>}
  ↓
.receive_commitments(self, Vec<commitment>) → Share(Scalar)
  ↓
PartyAwaitingShares{c, R, Vec, CounterpartyCommitted>} 
  ↓
.receive_shares(self, Vec<share>) → Signature{s, R}

```

Note:
For now, we will have message redundancy - meaning, each party will receive and verify its own messages 
as well as its counterparties' messages. This makes the protocol slightly simpler, but does incur a performance overhead. 
(Future work: potentially remove this redundancy).

Also, for now we will assume that all of the messages passed into each party state arrive in the same order 
(each party's message is in the same index). 
This allows us to skip the step of ordering them / assigning indexes. 
(Future work: allow for unordered inputs, have the parties sort them.)


    - Make `S = {(X_1, m_1), ..., (X_n, m_n)}` where `S` is the ordered set of public key (`X_i`) and message (`m_i`) pairs of all participants. 

### Party

Fields: none

Function: `new(...)`

Input: 
- transcript: `&mut Transcript` - a transcript to which the message to be signed has already been committed.
- privkey: `Scalar`
- message: `Message`

Operation:
- Make `X_i = g * x_i`.

Output:
- The next state in the protocol: `PartyAwaitingKeyMessages`
- The returned keymessage pair: `KeyMessage(X_i, message)`

### PartyAwaitingKeyMessages

Fields: 
- transcript: `Transcript`
- privkey: `Scalar`
- counterparties: `Vec<Counterparty>`

Input:
- `self`
- key_messages: `Vec<KeyMessage>`

Operation:
- Use the transcript to generate a random factor (the nonce), by committing to the privkey and passing in a `thread_rng`.
- Use the nonce to create a nonce commitment and precommitment
- Create a vector of `Counterparty`s by calling `Counterparty::new(...)` with the input keymessages.

Output: 
- The next state in the protocol: `PartyAwaitingPrecommitments` 
- The nonce precommitment: `NoncePrecommitment`

### PartyAwaitingPrecommitments

Fields: 
- transcript: `Transcript`
- multikey: `Multikey`
- privkey: `Scalar`
- nonce: `Scalar`
- nonce_commitment: `RistrettoPoint`
- counterparties: `Vec<Counterparty>`

Function: `receive_precommitments(...)`

Input: 
- `self`
- nonce_precommitments: `Vec<NoncePrecommitment>`

Operation:
- Call `precommit_nonce(...)` on each of `self.counterparties`, with the received `nonce_precommitments`. 
This will return `CounterpartyPrecommitted`s.

Output:
- the next state in the protocol: `PartyAwaitingCommitments`
- the nonce commitment: `NonceCommitment`

### PartyAwaitingCommitments

Fields:
- transcript: `Transcript`
- multikey: `Multikey`
- privkey: `Scalar`
- nonce: `Scalar`
- counterparties: `Vec<CounterpartyPrecommitted>`

Function: `receive_commitments(...)`

Input:
- `self`
- nonce_commitments: `Vec<NonceCommitment>`

Operation:
- Call `commit_nonce(...)` on each of `self.counterparties`, with the received `nonce_commitments`. 
This checks that the stored precommitments match the received commitments. 
If it succeeds, it will return `CounterpartyCommitted`s.
- Make `nonce_sum` = sum(`nonce_commitments`)
- Make `c` = challenge scalar after committing `multikey.aggregated_key()` and `nonce_sum` into the transcript
- Make `a_i` = `multikey.factor_for_key(self.privkey)`
- Make `s_i` = `r_i + c * a_i * x_i`, where `x_i` = `self.privkey` and `r_i` = `self.nonce`

Output: 
- The next state in the protocol: `PartyAwaitingShares`
- The signature share: `Share`

### PartyAwaitingShares

Fields:
- multikey: `Multikey`
- counterparties: `Vec<CounterpartyCommitted>`
- challenge: `Scalar`
- nonce_sum: `RistrettoPoint`

Function: `receive_shares(...)`

Input: 
- `self`
- shares: `Vec<Share>`

Operation:
- Call `sign(...)` on each of `self.counterparties`, with the received `shares`. 
This checks that the shares are valid, using the information in the `CounterpartyCommitted`. 
(Calling `receive_trusted_shares(...)` skips this step.)
- Make `s` = `sum(shares)`

Output
- The signature: `Signature { self.nonce_sum, s }`

## Protocol for counterparty state transitions
Counterparties are states stored internally by a party, that represent the messages received by from its counterparties. 

Counterparty state transitions overview:
```
Counterparty{pubkey}
  ↓
.precommit_nonce(precommitment)
  ↓
CounterpartyPrecommitted{precommitment, pubkey}
  ↓
.commit_nonce(commitment)
  ↓
CounterpartyCommitted{commitment, pubkey}
  ↓
.sign(share, challenge, multikey)
  ↓
 s_i

s_total = sum{s_i}
R_total = sum{R_i}
Signature = {s: s_total, R: R_total}
```

### Counterparty

Fields: pubkey

Function: `new(...)`

Input: 
- pubkey: `VerificationKey`

Operation:
- Create a new `Counterparty` instance with the input pubkey in the `pubkey` field

Output: 
- The new `Counterparty` instance



Function: `precommit_nonce(...)`

Input:
- precommitment: `NoncePrecommitment`

Operation:
- Create a new `CounterpartyPrecommitted` instance with `self.pubkey` and the precommitment
- Future work: receive pubkey in this function, and match against stored counterparties to make sure the pubkey corresponds. 
This will allow us to receive messages out of order, and do sorting on the party's end.

Output:
- `CounterpartyPrecommitted`

### CounterpartyPrecommitted

Fields:
- precommitment: `NoncePrecommitment`
- pubkey: `VerificationKey`

Function: `commit_nonce(...)`

Input: 
- commitment: `NonceCommitment`

Operation:
- Verify that `self.precommitment = commitment.precommit()`.
- If verification succeeds, create a new `CounterpartyCommitted` using `self.pubkey` and commitment.
- Else, return `Err(VMError::MusigShareError)`.

Output:
- `Result<CounterpartyCommitted, MusigShareError>`.

### CounterpartyCommitted

Fields:
- commitment: `NonceCommitment`
- pubkey: `VerificationKey`

Function: `sign(...)`

Input:
- share: `Scalar`
- challenge: `Scalar`
- multikey: `&Multikey`

Operation:
- Verify that `s_i * G == R_i + c * a_i * X_i`.
  `s_i` = share, `G` = [base point](#base-point), `R_i` = self.commitment, `c` = challenge, 
  `a_i` = `multikey.factor_for_key(self.pubkey)`, `X_i` = self.pubkey.
- If verification succeeds, return `Ok(share)`
- Else, return `Err(VMError::MusigShareError)`

Output:
- `Result<Scalar, VMError>`