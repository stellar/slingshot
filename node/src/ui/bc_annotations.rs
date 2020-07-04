use serde_json::Value as JsonValue;
use super::wallet::Balance;

trait JsonAnnotated {
    /// Encodes the object in a JSON value.
    fn as_json_annotated(&self) -> JsonValue;
}

impl JsonAnnotated for Balance {
    fn as_json_annotated(&self) -> JsonValue {
        unimplemented!()
    }
}

