use curve25519_dalek::scalar::Scalar;
use serde_json::Value as JsonValue;

use super::schema::*;
use super::user::User;

#[derive(Debug, Queryable, Insertable)]
pub struct AssetRecord {
    pub owner_id: String,
    pub alias: String,
    pub key_hex: String,
    pub flavor_hex: String,
}

struct AssetDefinition {
    pub issuance_key: Scalar,
    pub alias: String,
}

impl AssetDefinition {
    pub fn issuance_predicate(&self) -> zkvm::Predicate {
        let vkey = zkvm::VerificationKey::from_secret(&self.issuance_key);
        zkvm::Predicate::Key(vkey)
    }

    pub fn metadata(&self) -> zkvm::String {
        zkvm::String::Opaque(self.alias.as_bytes().to_vec())
    }

    pub fn flavor(&self) -> Scalar {
        zkvm::Value::issue_flavor(&self.issuance_predicate(), self.metadata())
    }
}

impl AssetRecord {
    /// Creates a new asset record with key derived from the alias.
    pub fn new(owner: &User, alias: impl Into<String>) -> Self {
        let alias = alias.into();
        let issuance_key = owner.xprv().derive_key(|t| {
            t.append_message(b"asset_alias", alias.as_bytes());
        });
        let adef = AssetDefinition {
            issuance_key,
            alias,
        };
        let flavor = adef.flavor();
        AssetRecord {
            owner_id: owner.id(),
            alias: adef.alias,
            key_hex: hex::encode(&adef.issuance_key.to_bytes()[..]),
            flavor_hex: hex::encode(flavor.as_bytes()),
        }
    }

    pub fn issuance_key(&self) -> Scalar {
        let mut bytes = [0u8; 32];
        let vec = hex::decode(&self.key_hex).expect("DB must contain valid asset_records.key_hex");
        bytes[..].copy_from_slice(&vec);
        Scalar::from_canonical_bytes(bytes)
            .expect("DB must contain canonical Scalar in asset_records.key_hex")
    }

    pub fn metadata(&self) -> zkvm::String {
        self.asset_definition().metadata()
    }

    pub fn flavor(&self) -> Scalar {
        self.asset_definition().flavor()
    }

    /// Converts the node to JSON object tree.
    pub fn to_json(&self) -> JsonValue {
        // stored json is guaranteed to be valid
        json!({
            "alias": self.alias,
            "prv": hex::encode(self.issuance_key().as_bytes()),
            "pub": hex::encode(self.asset_definition().issuance_predicate().to_point().as_bytes()),
            "flv": hex::encode(self.flavor().as_bytes())
        })
    }

    fn asset_definition(&self) -> AssetDefinition {
        AssetDefinition {
            issuance_key: self.issuance_key(),
            alias: self.alias.clone(),
        }
    }
}
