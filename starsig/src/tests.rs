use super::{BatchVerifier, Signature, StarsigError, VerificationKey};
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;

#[test]
fn sign_and_verify_single() {
    let privkey = Scalar::from(1u64);
    let sig = Signature::sign(&mut Transcript::new(b"example transcript"), privkey);

    let X = VerificationKey::from_secret(&privkey);

    assert!(sig
        .verify(&mut Transcript::new(b"example transcript"), X)
        .is_ok());

    let priv_bad = Scalar::from(2u64);
    let X_bad = VerificationKey::from_secret(&priv_bad);
    assert!(sig
        .verify(&mut Transcript::new(b"example transcript"), X_bad)
        .is_err());
    assert!(sig
        .verify(&mut Transcript::new(b"invalid transcript"), X)
        .is_err());
}

#[test]
fn empty_batch() {
    let batch = BatchVerifier::new(rand::thread_rng());
    assert_eq!(batch.verify(), Ok(()));
}
#[test]
fn sign_and_verify_batch() {
    let prv1 = Scalar::from(1u64);
    let prv2 = Scalar::from(2u64);
    let prv3 = Scalar::from(3u64);
    let sig1 = Signature::sign(&mut Transcript::new(b"example transcript 1"), prv1);
    let sig2 = Signature::sign(&mut Transcript::new(b"example transcript 2"), prv2);
    let sig3 = Signature::sign(&mut Transcript::new(b"example transcript 3"), prv3);

    let pub1 = VerificationKey::from_secret(&prv1);
    let pub2 = VerificationKey::from_secret(&prv2);
    let pub3 = VerificationKey::from_secret(&prv3);

    assert!(sig1
        .verify(&mut Transcript::new(b"example transcript 1"), pub1)
        .is_ok());
    assert!(sig2
        .verify(&mut Transcript::new(b"example transcript 2"), pub2)
        .is_ok());
    assert!(sig3
        .verify(&mut Transcript::new(b"example transcript 3"), pub3)
        .is_ok());

    let mut batch = BatchVerifier::new(rand::thread_rng());

    sig1.verify_batched(
        &mut Transcript::new(b"example transcript 1"),
        pub1,
        &mut batch,
    );
    sig2.verify_batched(
        &mut Transcript::new(b"example transcript 2"),
        pub2,
        &mut batch,
    );
    sig3.verify_batched(
        &mut Transcript::new(b"example transcript 3"),
        pub3,
        &mut batch,
    );

    assert!(batch.verify().is_ok());

    // Invalid batch (wrong message):

    let mut bad_batch = BatchVerifier::new(rand::thread_rng());

    sig1.verify_batched(
        &mut Transcript::new(b"example transcript 1"),
        pub1,
        &mut bad_batch,
    );
    sig2.verify_batched(&mut Transcript::new(b"wrong message"), pub2, &mut bad_batch);
    sig3.verify_batched(
        &mut Transcript::new(b"example transcript 3"),
        pub3,
        &mut bad_batch,
    );

    assert_eq!(bad_batch.verify(), Err(StarsigError::InvalidBatch));

    // Invalid batch (wrong key):

    let mut bad_batch = BatchVerifier::new(rand::thread_rng());

    sig1.verify_batched(
        &mut Transcript::new(b"example transcript 1"),
        pub1,
        &mut bad_batch,
    );
    sig2.verify_batched(
        &mut Transcript::new(b"example transcript 2"),
        pub1.clone(),
        &mut bad_batch,
    );
    sig3.verify_batched(
        &mut Transcript::new(b"example transcript 3"),
        pub3,
        &mut bad_batch,
    );

    assert_eq!(bad_batch.verify(), Err(StarsigError::InvalidBatch));

    // Invalid batch (wrong signature):

    let mut bad_batch = BatchVerifier::new(rand::thread_rng());

    sig1.verify_batched(
        &mut Transcript::new(b"example transcript 1"),
        pub1,
        &mut bad_batch,
    );
    sig1.verify_batched(
        &mut Transcript::new(b"example transcript 2"),
        pub2,
        &mut bad_batch,
    );
    sig3.verify_batched(
        &mut Transcript::new(b"example transcript 3"),
        pub3,
        &mut bad_batch,
    );

    assert_eq!(bad_batch.verify(), Err(StarsigError::InvalidBatch));
}
