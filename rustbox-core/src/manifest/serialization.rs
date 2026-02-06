use serde::{Serialize, de::DeserializeOwned};
use crate::error::RustBoxError;

pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, RustBoxError> {
    bincode::serialize(value)
        .map_err(|e| RustBoxError::Serialization(e.to_string()))
}

pub fn deserialize<T: DeserializeOwned>(data: &[u8]) -> Result<T, RustBoxError> {
    bincode::deserialize(data)
        .map_err(|e| RustBoxError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_deserialize_string() {
        let original = "hello world".to_string();
        let bytes = serialize(&original).unwrap();
        let decoded: String = deserialize(&bytes).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn test_serialize_deserialize_vec() {
        let original: Vec<u32> = vec![1, 2, 3, 4, 5];
        let bytes = serialize(&original).unwrap();
        let decoded: Vec<u32> = deserialize(&bytes).unwrap();
        assert_eq!(decoded, original);
    }
}
