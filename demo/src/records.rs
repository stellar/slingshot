use serde_json;
use curve25519_dalek::scalar::Scalar;

use super::schema::*;
use super::nodes::*;
use super::util;

// Stored data

#[derive(Debug,Queryable,Insertable)]
pub struct BlockRecord {
    pub height: i32, // FIXME: diesel doesn't allow u64 here...
    pub block_json: String,
    pub state_json: String, // latest state will be used for *the* network state
}

#[derive(Debug,Queryable,Insertable)]
pub struct AssetRecord {
    pub alias: String,
    pub key_json: String,
}

#[derive(Debug,Queryable,Insertable)]
pub struct NodeRecord {
    pub alias: String,
    pub state_json: String,
}

impl NodeRecord {
    pub fn new(node: Node) -> Self {
        Self {
            alias: node.wallet.alias.clone(),
            state_json: serde_json::to_string_pretty(&node).expect("JSON serialization should work for Node")
        }
    }

    pub fn node(&self) -> Node {
        serde_json::from_str(&self.state_json).expect("JSON decoding should work for NodeRecord")
    }
}


impl AssetRecord {
    /// Creates a new asset record with key derived from the alias.
    pub fn new(alias: impl Into<String>) -> Self {
        let alias = alias.into();
        let key = util::scalar_from_string(&alias);
        dbg!(&key);

        let keyjson = serde_json::to_string(&key).expect("Key should be encoded well");
        dbg!(&keyjson);

        let key2:serde_json::Value = serde_json::from_str(&keyjson).expect("json String->json::Value fail");
        dbg!(&key2);
        
        let key2:Scalar = serde_json::from_str(&keyjson).expect("json string->Scalar fail");
        dbg!(&key2);

        AssetRecord {
            alias,
            key_json: serde_json::to_string(&key).expect("Issuance key should be encoded well")
        }
    }

    pub fn issuance_key(&self) -> Scalar {
        serde_json::from_str(&self.key_json).expect("Should decode issuance key well from json")
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
}

