# Signatures: Engineering design doc

vanilla design:
- single message 
- no recursion
- no defense against russell's attack

2 parts of protocol:
1. key aggregation
	multikey
	keeps transcript, feeds pubkeys to transcript
	clone / fork transcript to make per-key factors
2. signing & verifying
	each party has state, wants to go to next state by verifying & performing computations. so you can "encode validity of something in the type".
	party transitions need to be non-replayable (is this true?)

dealer & parties in rangeproof:
- dealer accumulates all factors, holds onto the transcript, gives challenges
- parties don't have to know about other parties, who's failing, transcript, etc.

oleg says: shouldn't have dealer


create 3 counterparty structs,
transition state machine that says that it's precommitted. 

first counterparty state - hold pubkey

receive vector of nonceprecommitments (assume for simlicity that it's in the same order as list of counterparties).
zip those together, transition into new state (counterpartyprecommittedstate). give to the next party state (partyawaitingcommitments)

receive vector of noncecommitments, zip those with counterpartyprecommittedstate to make new state: counterpartycommittedstate. 
(can fail: collect the zip into a result of vec<>).
(check is implemented on a method on counterpartyprecommittedstate).
(drops the precommitment, but holds onto the pubkey)
if this doesn't fail, then the party makes its signature share, send

receive signature shares. if receive untrusted, then transition counterparties (counterpartycommittedstate) -> sign -> counterpartyshares.
if receive trusted, then can throw way counterparties and just make a signature from adding summed up nonce (saved in state since we have to sum it up before anyways.)

counterpartycommitted <- signature -> then can verify that it's valid.

cleaner right now to have redundancy: each party will receive & verify its own stuff. (don't have to do weird filtering, but it is a performance overhead).

