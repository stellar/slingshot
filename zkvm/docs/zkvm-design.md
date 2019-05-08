# ZkVM: fast, private, flexible blockchain contracts

* [Introduction](#introduction)
* [Transactions](#transactions)
* [Program execution](#program-execution)
* [Contracts](#contracts)
* [Constraints](#constraints)
* [Scalability](#scalability)
* [Privacy](#privacy)
* [Performance](#performance)
* [Conclusion](#conclusion)
* [Future work](#future-work)
* [Authors](#authors)
* [References](#references)



## Introduction

TBD: start with first principles, not as a diff with TxVM. 
We need a medium for issued assets: why it should be scalable, efficient, private, customizable and simple.

TBD: scalability+speed lowers adoption barriers

TBD: privacy lowers adoption barriers - less need to keep tx data in siloed ledgers

TBD: customization allows keeping core protocol w/o governance and babysitting - increases confidence.

TBD: simple: powerful composition of simpler ideas instead of complex tools or many layers of abstractions.


## Architecture

TBD: txs

TBD: programs

TBD: contracts and predicates

TBD: constraints

TBD: blockchain state


## Consensus

TBD: out of scope, can be used in PoW/PoS/SCP/single-host environments


## Scalability

TBD: VM execution is decoupled from state updates

TBD: small utxo-based state machine

TBD: trimming of state with utreexo, with ability to track all or some of utxos

TBD: SPV tracking for updating utxo proofs and watching payment channel state


## Privacy

TBD: qty and flavors are encrypted

TBD: asset flow is hidden per-transaction: coinjoin possible for anonymity.

TBD: contracts operate on encrypted data

TBD: programs ARE NOT compiled to constraint system


## Contracts

TBD: happy path VS other path, and Taproot

TBD: "blockchain as a court"

TBD: example of multi-factor custody

TBD: example of payment channel

TBD: example of collateralized loan contract

TBD: Rust APIs instead of Ivy. 


## Performance

TBD: benchmarks and estimations for CPU throughput, latency

TBD: data bandwidth for coinjoined and non-joined payments, 

TBD: bandwidth for SPV clients tracking headers and trimmed state updates


## Conclusion

ZkVM is a comprehensive hydrid solution that brings together results of years of research and development
of many people in the applied cryptography and cryptocurrency space.

It strikes the right balance between various, partially conflicting requirements, producing a robust
technology stack for the global financial system of the future.


## References

* Bitcoin
* Ethereum
* Coinjoin
* Confidential Assets
* Taproot
* Musig
* TxVM
* Ivy
* Ristretto
* Bulletproofs
* Nick Szabo, [Secure Property Titles with Owner Authority](http://nakamotoinstitute.org/secure-property-titles/)

* Slingshot projects:
	* ZkVM
	* Keytree
	* Musig
