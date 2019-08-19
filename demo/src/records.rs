use curve25519_dalek::scalar::Scalar;

use super::nodes::*;
use super::schema::*;
use super::util;

// Stored data

#[derive(Debug, Queryable, Insertable)]
pub struct BlockRecord {
    pub height: i32, // FIXME: diesel doesn't allow u64 here...
    pub block_json: String,
    pub state_json: String, // latest state will be used for *the* network state
}

#[derive(Debug, Queryable, Insertable)]
pub struct AssetRecord {
    pub alias: String,
    pub key_json: String,
}

#[derive(Debug, Queryable, Insertable)]
pub struct NodeRecord {
    pub alias: String,
    pub state_json: String,
}

impl NodeRecord {
    pub fn new(node: Node) -> Self {
        Self {
            alias: node.wallet.alias.clone(),
            state_json: util::to_json(&node),
        }
    }

    /// Converts the record to the Node instance.
    pub fn node(&self) -> Node {
        util::from_valid_json(&self.state_json)
    }

    /// Converts the node to JSON object tree.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::from_str(&self.state_json)
            .expect("Stored json state must be correctly encoded.")
    }
}

impl AssetRecord {
    /// Creates a new asset record with key derived from the alias.
    pub fn new(alias: impl Into<String>) -> Self {
        let alias = alias.into();
        let key = util::scalar_from_string(&alias);
        AssetRecord {
            alias,
            key_json: util::to_json(&key),
        }
    }

    pub fn issuance_key(&self) -> Scalar {
        util::from_valid_json(&self.key_json)
    }

    pub fn issuance_predicate(&self) -> zkvm::Predicate {
        let vkey = zkvm::VerificationKey::from_secret(&self.issuance_key());
        zkvm::Predicate::Key(vkey)
    }

    pub fn metadata(&self) -> zkvm::String {
        zkvm::String::Opaque(self.alias.as_bytes().to_vec())
    }

    pub fn flavor(&self) -> Scalar {
        zkvm::Value::issue_flavor(&self.issuance_predicate(), self.metadata())
    }

    /// Converts the node to JSON object tree.
    pub fn to_json(&self) -> serde_json::Value {
        // stored json is guaranteed to be valid
        json!({
            "alias": self.alias,
            "prv": serde_json::from_str::<serde_json::Value>(&self.key_json).expect("DB should contain valid key_json"),
            "pub": hex::encode(self.issuance_predicate().to_point().as_bytes())
        })
    }
}
