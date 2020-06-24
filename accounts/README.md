# ZkVM Accounts

A low-level utility protocol to implement accounts on top of UTXOs in ZkVM.

This crate provides:

* _Key derivation_ using Xprv/Xpubs and sequence numbers to keep one key for all payments in the account.
* _Receivers_ for interactive billing systems.
* _Addresses_ for non-interactive payments.
