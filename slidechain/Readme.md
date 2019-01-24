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
