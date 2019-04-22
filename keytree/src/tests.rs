use super::*;
use hex;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

#[test]
fn random_xprv_test() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let xprv = Xprv::random(&mut rng);

    // the following are hard-coded based on the previous seed
    assert_eq!(
        to_hex_32(xprv.xpub.dk),
        "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
    );
    assert_eq!(
        hex::encode(xprv.scalar.as_bytes()),
        "4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c901"
    );
}

#[test]
fn random_xprv_derivation_test() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let xprv = Xprv::random(&mut rng).derive_intermediate_key(|t| {
        t.commit_u64(b"account_id", 34);
    });

    assert_eq!(
        hex::encode(xprv.scalar.as_bytes()),
        "55d65740c47cff19c35c2787dbc0e207e901fbb311caa4d583da8efdc7088b03"
    );
    assert_eq!(
        to_hex_32(xprv.xpub.dk),
        "36e435eabc2a562ef228b82b399fbd004b2cc64103313fa673bd1fca0971f59d"
    );
    assert_eq!(
        to_hex_32(xprv.xpub.pubkey.as_compressed().to_bytes()),
        "7414c0c5238c2277318ba3e51fc6fb8e836a2d9b4c04508f93cd5a455422221b"
    );
}

#[test]
fn random_xprv_leaf_test() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let xprv = Xprv::random(&mut rng).derive_key(|t| {
        t.commit_u64(b"invoice_id", 10034);
    });

    assert_eq!(
        hex::encode(xprv.as_bytes()),
        "a71e5435c3374eef60928c3bac1378dcbc91bc1d554e09242247a0861fd12c0c"
    );
}

#[test]
fn serialize_xprv_test() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let xprv = Xprv::random(&mut rng);
    let xprv_bytes = xprv.to_bytes();

    assert_eq!(
        to_hex_64(xprv_bytes),
        "4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c9019f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
    );
}

#[test]
fn deserialize_xprv_test() {
    let xprv_bytes = hex::decode("4a53c3fbbc59970ee5f85af813875dffc13a904a2e53ae7e65fa0dea6e62c9019f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed").unwrap();
    let xprv = Xprv::from_bytes(&xprv_bytes).unwrap();

    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let expected_xprv = Xprv::random(&mut rng);

    assert_eq!(xprv.xpub.dk, expected_xprv.xpub.dk);
    assert_eq!(xprv.scalar, expected_xprv.scalar);
}

#[test]
fn random_xpub_test() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let xprv = Xprv::random(&mut rng);
    let xpub = xprv.to_xpub();

    // hex strings are hard-coded based on the previous seed
    assert_eq!(
        to_hex_32(xpub.dk),
        "9f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
    );
    assert_eq!(
        to_hex_32(xpub.pubkey.to_bytes()),
        "9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b808"
    );
}

#[test]
fn serialize_xpub_test() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let xprv = Xprv::random(&mut rng);
    let xpub = xprv.to_xpub();

    assert_eq!(
        to_hex_64(xpub.to_bytes()),
        "9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b8089f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed"
    );
}

#[test]
fn deserialize_xpub_test() {
    let xpub_bytes = hex::decode("9c66a339c8344f922fc3206cb5dae814a594c0177dd3235c254d9c409a65b8089f07e7be5551387a98ba977c732d080dcb0f29a048e3656912c6533e32ee7aed").unwrap();
    let xpub = Xpub::from_bytes(&xpub_bytes).unwrap();

    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let expected_xprv = Xprv::random(&mut rng);
    let expected_xpub = expected_xprv.to_xpub();

    assert_eq!(xpub.dk, expected_xpub.dk);
    assert_eq!(xpub.pubkey, expected_xpub.pubkey);
    assert_eq!(
        xpub.pubkey.as_compressed(),
        expected_xpub.pubkey.as_compressed()
    );
}

#[test]
fn random_xpub_derivation_test() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let xprv = Xprv::random(&mut rng);
    let xpub = xprv.to_xpub().derive_intermediate_key(|t| {
        t.commit_u64(b"account_id", 34);
    });

    assert_eq!(
        to_hex_32(xpub.dk),
        "36e435eabc2a562ef228b82b399fbd004b2cc64103313fa673bd1fca0971f59d"
    );
    assert_eq!(
        to_hex_32(xpub.pubkey.to_bytes()),
        "7414c0c5238c2277318ba3e51fc6fb8e836a2d9b4c04508f93cd5a455422221b"
    );
}

#[test]
fn random_xpub_leaf_test() {
    let seed = [0u8; 32];
    let mut rng = ChaChaRng::from_seed(seed);
    let xprv = Xprv::random(&mut rng);
    let pubkey = xprv.to_xpub().derive_key(|t| {
        t.commit_u64(b"invoice_id", 10034);
    });

    assert_eq!(
        hex::encode(pubkey.as_bytes()),
        "a202e8a0b6fb7123bf1e2aaaf90ed9c3c55f7d1975ed4b63b4417e5d7397c048"
    );
}

fn to_hex_32(input: [u8; 32]) -> String {
    return hex::encode(&input[..]);
}

fn to_hex_64(input: [u8; 64]) -> String {
    return hex::encode(&input[..]);
}
