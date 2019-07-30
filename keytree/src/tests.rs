use super::*;
use hex;
use rand::SeedableRng;
use rand_chacha::ChaChaRng;

#[test]
fn test_vectors() {
    let root_prv = Xprv::default();
    let root_pub = root_prv.to_xpub();
    assert_eq!(
        to_hex_64(root_prv.to_bytes()),
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        to_hex_64(root_pub.to_bytes()),
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );

    let child_prv = root_prv.derive_intermediate_key(|prf| prf.append_u64(b"index", 1));
    let child_pub = root_pub.derive_intermediate_key(|prf| prf.append_u64(b"index", 1));
    assert_eq!(
        to_hex_64(child_prv.to_bytes()),
        "ba9bead5df738767ca184900a4a09ce8afe9f7696e8d3ac1fd99f607a785bf005237586d5b496618a49a876e9a7e077b1715f8635b41b48edcaf2934ebe62683"
    );
    assert_eq!(
        to_hex_64(child_pub.to_bytes()),
        "2ec9d53d9d43b86c73694f4acd4be1c274a3cf8d7512e91acebafc0ed884dd475237586d5b496618a49a876e9a7e077b1715f8635b41b48edcaf2934ebe62683"
    );
    assert_eq!(
        to_hex_64(child_prv.to_xpub().to_bytes()),
        "2ec9d53d9d43b86c73694f4acd4be1c274a3cf8d7512e91acebafc0ed884dd475237586d5b496618a49a876e9a7e077b1715f8635b41b48edcaf2934ebe62683"
    );

    // Note: the leaf keys must be domain-separated from the intermediate keys, even if using the same PRF customization
    let child2_prv = child_prv.derive_intermediate_key(|prf| prf.append_u64(b"index", 1));
    let child2_pub = child_pub.derive_intermediate_key(|prf| prf.append_u64(b"index", 1));
    assert_eq!(
        to_hex_64(child2_prv.to_bytes()),
        "d4719a691dc4e97b27abfc50764d0369a197b3d03b049f0654d4872dd5f01f02f334cb814294776de8551a4e6382c14d05ad2eb6d6391e87069a3fbe2e6ecf77"
    );
    assert_eq!(
        to_hex_64(child2_pub.to_bytes()),
        "1210a34624dfddb312da90ad5e2d3d4649d7eb50d44dad00972d1e1f422a4f29f334cb814294776de8551a4e6382c14d05ad2eb6d6391e87069a3fbe2e6ecf77"
    );
    assert_eq!(
        to_hex_64(child2_prv.to_xpub().to_bytes()),
        "1210a34624dfddb312da90ad5e2d3d4649d7eb50d44dad00972d1e1f422a4f29f334cb814294776de8551a4e6382c14d05ad2eb6d6391e87069a3fbe2e6ecf77"
    );

    let leaf_prv = child_prv.derive_key(|prf| prf.append_u64(b"index", 1));
    let leaf_pub = child_pub.derive_key(|prf| prf.append_u64(b"index", 1));
    assert_eq!(
        hex::encode(leaf_prv.to_bytes()),
        "a7a8928dfeae1479a7bf908bfa929b714a62fe334b68e4557105414113ffca04"
    );
    assert_eq!(
        hex::encode(leaf_pub.to_bytes()),
        "52ea0c9ce1540e65041565a1057aa6965bbb5b42709c1109da16609248a9d679"
    );
    assert_eq!(
        hex::encode(VerificationKey::from_secret(&leaf_prv).to_bytes()),
        "52ea0c9ce1540e65041565a1057aa6965bbb5b42709c1109da16609248a9d679"
    );
}

#[test]
fn test_defaults() {
    let default_xprv = Xprv::default();
    let default_xpub = Xpub::default();
    assert_eq!(
        to_hex_64(default_xprv.to_bytes()),
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        to_hex_64(default_xpub.to_bytes()),
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        to_hex_64(default_xpub.to_bytes()),
        to_hex_64(default_xprv.to_xpub().to_bytes())
    );

    let default_xprv = Xprv::from_bytes(&hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
    assert_eq!(
        to_hex_64(default_xprv.to_bytes()),
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    let default_xpub = Xpub::from_bytes(&hex::decode("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000").unwrap()).unwrap();
    assert_eq!(
        to_hex_64(default_xpub.to_bytes()),
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
}

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
    let xprv = Xprv::random(&mut rng).derive_intermediate_key(|prf| {
        prf.append_u64(b"account_id", 34);
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
    let xprv = Xprv::random(&mut rng).derive_key(|prf| {
        prf.append_u64(b"invoice_id", 10034);
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
    let xpub = xprv.to_xpub().derive_intermediate_key(|prf| {
        prf.append_u64(b"account_id", 34);
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
    let pubkey = xprv.to_xpub().derive_key(|prf| {
        prf.append_u64(b"invoice_id", 10034);
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
