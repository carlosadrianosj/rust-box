use hmac::Hmac;
use sha2::Sha256;

use super::{CryptoError, Result};
use crate::constants::{MASTER_KEY_LEN, PBKDF2_ITERATIONS, PBKDF2_SALT_LEN};

/// Derive a 32-byte master key from a password and salt using PBKDF2-HMAC-SHA256.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
) -> Result<[u8; MASTER_KEY_LEN]> {
    if salt.len() < PBKDF2_SALT_LEN {
        return Err(CryptoError::Pbkdf2Derive(format!(
            "salt too short: expected at least {PBKDF2_SALT_LEN}, got {}",
            salt.len()
        )));
    }

    let mut output = [0u8; MASTER_KEY_LEN];
    pbkdf2::pbkdf2::<Hmac<Sha256>>(password, salt, iterations, &mut output)
        .map_err(|e| CryptoError::Pbkdf2Derive(e.to_string()))?;

    Ok(output)
}

/// Derive master key with default iteration count.
pub fn derive_master_key_default(password: &[u8], salt: &[u8]) -> Result<[u8; MASTER_KEY_LEN]> {
    derive_master_key(password, salt, PBKDF2_ITERATIONS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key_deterministic() {
        let password = b"my_strong_password";
        let salt = [0x42u8; 32];

        let key1 = derive_master_key(password, &salt, 1000).unwrap();
        let key2 = derive_master_key(password, &salt, 1000).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_master_key_different_passwords() {
        let salt = [0x42u8; 32];
        let key1 = derive_master_key(b"password1", &salt, 1000).unwrap();
        let key2 = derive_master_key(b"password2", &salt, 1000).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_master_key_different_salts() {
        let password = b"same_password";
        let key1 = derive_master_key(password, &[0x01; 32], 1000).unwrap();
        let key2 = derive_master_key(password, &[0x02; 32], 1000).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_master_key_salt_too_short() {
        let result = derive_master_key(b"password", &[0x01; 16], 1000);
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_master_key_output_length() {
        let key = derive_master_key(b"test", &[0x42; 32], 1000).unwrap();
        assert_eq!(key.len(), 32);
    }
}
