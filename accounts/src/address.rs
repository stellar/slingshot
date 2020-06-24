//! Address protocol implementation
//!
//! Address is a 64-byte string that allows anyone to deliver payment w/o exchanging Receivers.
//!
//! Sending funds this way incurs a bit of overhead: extra `data` entry in the transaction,
//! with 72 bytes of data.
//!
//! Address consists of two 32-byte public keys (ristretto255 points): control key and encryption key.
//! Encryption key is used to encrypt the payment amount and arbitrary additional data,
//! while the control key allows spending the received funds.

// TBD.
