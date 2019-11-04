use std::time::SystemTime;

/// Returns the current system time.
pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("SystemTime should work")
        .as_millis() as u64
}

/// Force-decodes json string
pub fn from_valid_json<'a, T>(string: &'a str) -> T
where
    T: serde::de::Deserialize<'a>,
{
    serde_json::de::from_str_with_binary_mode(string, serde_json::BinaryMode::Hex)
        .expect("from_valid_json expects a valid JSON string")
}

/// Encodes object to JSON-encoded String
pub fn to_json<T>(value: &T) -> String
where
    T: serde::ser::Serialize,
{
    let mut vec = Vec::with_capacity(128);
    let mut ser = serde_json::ser::Serializer::with_formatter_and_binary_mode(
        &mut vec,
        serde_json::ser::PrettyFormatter::default(),
        serde_json::BinaryMode::Hex,
    );
    value
        .serialize(&mut ser)
        .expect("Serialization should work");
    String::from_utf8(vec).expect("Should not emit invalid UTF-8")
}

/// Encodes object to a JSON object
pub fn to_json_value<T>(value: &T) -> serde_json::Value
where
    T: serde::ser::Serialize,
{
    serde_json::from_str(&to_json(value)).expect("Serialization to JSON value should work")
}
