# Signatures: Engineering design doc

This is a signature scheme for signing messages. 
This design doc describes the protocol for signing a single message with one public key 
(where the public key can be created from a single party's private key, 
or from the aggregation of multiple public keys),
and for signing multiple messages with multiple public keys.

In future iterations, we can consider signing with public keys that are nested aggregations of public keys.

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

### MusigContext

This is a private trait with three functions:
- `commit(&self, &mut transcript)`: takes a mutable transcript, and commits the internal context to the transcript.
- `challenge(&self, &verification_key, &mut transcript) -> Scalar`: takes a public key and mutable transcript, and returns the 
  suitable challenge for that public key. 
- `get_pubkeys(&self) -> Vec<VerificationKey>`: returns the associated public keys.

### Multikey 

Implements MusigContext

Fields:
- transcript: `Transcript`. All of the pubkeys that the multikey are created from are committed to this transcript. 
- aggregated_key: `VerificationKey`
- public_keys: `Vec<VerificationKey>`

Functions: 
- `Multikey::new(...) -> Self`: detailed more in [key aggregation](#key-aggregation) section. 

- `Multikey::commit(&self, &mut transcript)`: Commits `self.aggregated_key` to the input `transcript` with label "X".

- `Multikey::challenge(&self, &verification_key, &mut transcript) -> Scalar`: 
  Computes challenge `c_i = a_i * c`, where `a_i = H_agg(<L>, X_i)` and `c = H_sig(X, R, m)`.

  For calculating `a_i`, `<L>` (the list of pubkeys that go into the aggregated pubkey)
  has already been committed into `self.transcript`. Therefore this function simply clones `self.transcript`, 
  commits the verification key (`X_i`) into the transcript with label "X_i", 
  and then squeezes the challenge scalar `a_i` from the transcript with label "a_i".

  For calculating `c`: the message `m`, the nonce commitment sum `R`, and the aggregated key `X` 
  have already been committed to the input `transcript`.
  It then gets the challenge scalar `c` from the transcript with label "c".

  Returns `c_i = a_i * c`.

- `Multikey::aggregated_key(&self) -> VerificationKey`: returns the aggregated key stored in the multikey, `self.aggregated_key`.  

- `Multikey::get_pubkeys(&self) -> Vec<VerificationKey>`: returns the list of public keys, `self.public_keys`.

### Multimessage

Implements MusigContext

Fields:
- pairs: `Vec<(VerificationKey, [u8])>`

Functions:
- `Multimessage::new(Vec<(VerificationKey, [u8])>) -> Self`: creates a new MultiMessage instance using the inputs.

- `Multimessage::commit(&self, &mut transcript)`: 
  It commits to the number of pairs, with `transcript.commit_u64(self.pairs.len())`. 
  It then commits each of the pairs in `self.pairs` to the input `transcript`,
  by iterating through `self.pairs` and committing the `VerificationKey` with label "X" and the message with label "m".

- `Multimessage::challenge(&self, &verification_key, &mut transcript) -> Scalar`: 
  Computes challenge `c_i = H(R, <S>, i)`.
  The nonce commitment sum `R`, and the pairs `<S>`, have already been committed to the input `transcript`.

  It forks the input transcript by cloning it. The non-forked transcript (input `transcript`) gets domain 
  separated with `transcript.commit("dom-sep", "Musig.multi-message-boundary")`.
  This prevents later steps from being able to get the same challenges that come from the forked transcript.
 
  It then figures out what its index `i` is, by matching the input `verification_key` against all the keys in 
  `self.pairs`. The index `i` is the index of pair of the key it matches to. 
  It commits `i` to the forked transcript with label "i".
  It then gets and returns the challenge scalar `c_i` from the forked transcript with label "c_i".

- `Multimessage::get_pubkeys(&self) -> Vec<VerificationKey>`: returns the list of public keys, without the messages, from `self.pairs`.


### Signature

A signature is comprised of a scalar `s`, and a RistrettoPoint `R`. 
In the simple Schnorr signature case, `s` represents the Schnorr signature scalar and `R` represents the nonce commitment. 
In the Musig signature case, `s` represents the sum of the Schnorr signature scalars of each party, or `s = sum_i (s_i)`. 
`R` represents the sum of the nonce commitments of each party, or `R = sum_i (R_i)`. 

Functions:
- `Signature::verify(...) -> Result<(), VMError>`
- `Signature::verify_multimessage(...) -> Result<(), VMError>`
For more detail, see the [verification](#verifying) section.

## Operations

### Key Aggregation

Key aggregation happens in the `Multikey::new(...)` function. 

Input:
- pubkeys: `Vec<VerificationKey>`. This is a list of compressed public keys that will be aggregated, 
  as long as they can be decompressed successfully.

Operation:
- Create a new transcript using the tag "Musig.aggregated-key". 
- Commit all the pubkeys to the transcript. 
The transcript state corresponds to the commitment `<L>` in the Musig paper: `<L> = H(X_1 || X_2 || ... || X_n)`.
- Create `aggregated_key = sum_i ( a_i * X_i )`. 
Iterate over the pubkeys, compute the factor `a_i = H(<L>, X_i)`, and add `a_i * X_i` to the aggregated key.

Output:
- a new `Multikey`, with the transcript and aggregated key detailed above.

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
    - Signature { `s`, `R` }

2. Make a Schnorr signature with one aggregated key (`Multikey`), derived from multiple public keys.
    - Create a `Multikey`. For more information, see the [key aggregation](#key-aggregation) section.

    Each party gets initialized, and makes and shares its nonce precommitment.
    - Call `Party::new(transcript, privkey, multikey)`.
    - Get back `PartyAwaitingPrecommitments` and a `NoncePrecommitment`.
    - Share your `NoncePrecommitment`, and receive other parties' `NoncePrecommitment`s. 

    Each party receives and stores other parties' precommitments, and shares its nonce commitment.
    - Call `receive_precommitments(precommitments)` on your `PartyAwaitingPrecommitments` state, 
    inputting a vector of all parties' precommitments.
    - Get back `PartyAwaitingCommitments` and a `NonceCommitment`.
    - Share your `NonceCommitment`, and receive other parties' `NonceCommitment`s.

    Each party receives and validates other parties' commitments, and shares its signature share.
    - Call `receive_commitments(commitments)` on your `PartyAwaitingCommitments` state, 
    inputting a vector of all parties' commitments.
    - Get back `PartyAwaitingShares` and a `Share`.
    - Share your `Share`, and receive other parties' `Share`s.

    Each party receives and validates other parties' signature shares, and returns a signature.
    - Call `receive_shares(share)` on your `PartyAwaitingShares`.
    - Get back `Signature`. You are done!

    For more information on each of these states and steps, see the [protocol for party state transitions](#protocol-for-party-state-transitions).

3. Make a Schnorr signature with multiple public keys and multiple messages, in a way that is safe from Russell's attack.
    - Create a `Multimessage` context by calling `Multimessage::new(...)`. 
      See the [multimessage](#multimessage) section for more details.

    For each party that is taking part in the signing:
    - Call `Party::new(transcript, privkey, multimessage)`.
    - All following steps are the same as in protocol #2.

### Verifying

There are several paths to verifying: 
1. Normal Schnorr signature verification (covers cases #1 and #2 in [signing section](#signing)).
    Function: `Signature::verify(...)`

    Input: 
    - `&self`
    - transcript: `&mut Transcript` - a transcript to which the signed message has already been committed.
    - P: `VerificationKey`

    Operation:
    - Make `c = H(X, R, m)`. Since the transcript already has the message `m` committed to it, 
    the function only needs to commit `X` with label "X" and `R` with label "R", 
    and then get the challenge scalar `c` with label "c".
    - Decompress verification key `P`. If this fails, return `Err(VMError::InvalidPoint)`.
    - Check if `s * G == R + c * P`. `G` is the [base point](#base-point).

    Output:
    - `Ok(())` if verification succeeds, or `Err(VMError)` if the verification or point decompression fail.

2. Multi-message Schnorr signature verification (covers case #3 in [signing section](#signing)).
    Function: `Signature::verify_multimessage(...)`

    Input: 
    - `&self`
    - transcript: `&mut Transcript` - a transcript to which the signed message has already been committed.
    - multimessage: `Multimessage` 

    Operation:
    - Use `multimessage.commit(&mut transcript)` to commit the key
    - Commit `self.R` to the transcript with label "R".
    - Use `multimessage.challenge(pubkey, &mut transcript)` to get the per-pubkey challenge `c_i`.
    - Sum up `sum_i(X_i * c_i)` into `cX`. This requires decompressing each pubkey to make `X_i`. 
      If the decompression fails, return `Err(VMError::InvalidPoint)`.
    - Check if `s * G == cX + R`. `G` is the [base point](#base-point).

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
.new(transcript, privkey, context) → NoncePrecommitment([u8; 32])
  ↓
PartyAwaitingPrecommitments{transcript, privkey, context, nonce, noncecommitment, Vec<Counterparty>}
  ↓
.receive_precommitments(self, Vec<precommitment>) → NonceCommitment(RistrettoPoint)
  ↓
PartyAwaitingCommitments{transcript, privkey, context, nonce, Vec<CounterpartyPrecommitted>}
  ↓
.receive_commitments(self, Vec<commitment>) → Share(Scalar)
  ↓
PartyAwaitingShares{context, c, R, Vec, CounterpartyCommitted>} 
  ↓
.receive_shares(self, Vec<share>) → Signature{s, R}

```

Note:
For now, we will have message redundancy - meaning, each party will receive and verify its own messages 
as well as its counterparties' messages. This makes the protocol slightly simpler, but does incur a performance overhead. 
(Future work: potentially remove this redundancy).

Also, for now we will assume that all of the messages passed into each party state arrive in the same order 
(each party's message is in the same index). This allows us to skip the step of ordering them / assigning indexes. 
(Future work: allow for unordered inputs, have the parties sort them.)

### Party

Fields: none

Function: `new<C: MusigContext>(...)`

Input: 
- transcript: `&mut Transcript` - a transcript to which the message to be signed has already been committed.
- privkey: `Scalar`
- context: `C`

Operation:
- Use the transcript to generate a random factor (the nonce), by committing to the privkey and passing in a `thread_rng`.
- Use the nonce to create a nonce commitment and precommitment
- Clone the transcript
- Create a vector of `Counterparty`s by calling `Counterparty::new(...)` with the each of the pubkeys in the context. 
  Get the list of pubkeys by calling `context::get_pubkeys()`.

Output:

- The next state in the protocol: `PartyAwaitingPrecommitments` 
- The nonce precommitment: `NoncePrecommitment`

### PartyAwaitingPrecommitments<C: MusigContext> 

Fields: 
- transcript: `Transcript`
- context: `C`
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

### PartyAwaitingCommitments<C: MusigContext>

Fields:
- transcript: `Transcript`
- context: `C`
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
- Commit the context to `self.transcript` by calling `MusigContext::challenge(...)`.
- Make `nonce_sum` = sum(`nonce_commitments`)
- Commit `nonce_sum` to `self.transcript` with label "R".
- Make `c_i` = `context.challenge(self.privkey, &mut transcript)`
- Make `s_i` = `r_i + c_i * x_i`, where `x_i` = `self.privkey` and `r_i` = `self.nonce`

Output: 
- The next state in the protocol: `PartyAwaitingShares`
- The signature share: `Share`

### PartyAwaitingShares<C: MusigContext>

Fields:
- context: `C`
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
.sign(share, challenge, context)
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
- context: `VerificationKey`

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

Function: `sign<C: MusigContext>(...)`

Input:
- share: `Scalar`
- context: `C`
- transcript: `&mut transcript`

Operation:
- Verify that `s_i * G == R_i + c_i * X_i`.
  `s_i` = share, `G` = [base point](#base-point), `R_i` = self.commitment,
  `c_i` = `context.challenge(self.pubkey, &mut transcript)`, `X_i` = self.pubkey.
- If verification succeeds, return `Ok(share)`
- Else, return `Err(VMError::MusigShareError)`

Output:
- `Result<Scalar, VMError>`
