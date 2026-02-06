use p256::PublicKey as P256PublicKey;
use p256::EncodedPoint as P256EncodedPoint;
use elliptic_curve::sec1::FromEncodedPoint;
use sha2::{Sha256, Digest};

use super::{CryptoError, Result};
use crate::traits::random::SecureRandom;

/// ECDH P-256 key pair.
#[derive(Debug)]
pub struct P256KeyPair {
    pub private_key: Vec<u8>,
    pub public_key: Vec<u8>,
}

/// Generate a new ECDH P-256 key pair using the provided SecureRandom source.
pub fn generate_p256_keypair(rng: &dyn SecureRandom) -> std::result::Result<P256KeyPair, CryptoError> {
    let mut key_bytes = [0u8; 32];
    rng.fill_bytes(&mut key_bytes)
        .map_err(|e| CryptoError::EcdhKeyGen(e.to_string()))?;

    // Retry if the random bytes don't form a valid scalar (extremely unlikely)
    let secret = p256::SecretKey::from_bytes((&key_bytes).into())
        .map_err(|e| CryptoError::EcdhKeyGen(format!("invalid secret key: {e}")))?;

    let public = secret.public_key();
    let encoded = P256EncodedPoint::from(public);

    Ok(P256KeyPair {
        private_key: secret.to_bytes().to_vec(),
        public_key: encoded.as_bytes().to_vec(),
    })
}

/// Compute ECDH P-256 shared secret, then SHA-256 hash it.
/// Returns SHA256(shared_secret), which is 32 bytes.
pub fn compute_p256_shared_secret(
    private_key: &[u8],
    peer_public_key: &[u8],
) -> Result<Vec<u8>> {
    let secret_key = p256::SecretKey::from_bytes(private_key.into())
        .map_err(|e| CryptoError::EcdhSharedSecret(format!("invalid private key: {e}")))?;

    let encoded_point = P256EncodedPoint::from_bytes(peer_public_key)
        .map_err(|e| CryptoError::EcdhSharedSecret(format!("invalid public key encoding: {e}")))?;

    let peer_pub = P256PublicKey::from_encoded_point(&encoded_point);
    if peer_pub.is_none().into() {
        return Err(CryptoError::InvalidPublicKey);
    }
    let peer_pub = peer_pub.unwrap();

    let shared_secret = p256::ecdh::diffie_hellman(
        secret_key.to_nonzero_scalar(),
        peer_pub.as_affine(),
    );

    let hash = Sha256::digest(shared_secret.raw_secret_bytes());
    Ok(hash.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRandom;

    impl SecureRandom for TestRandom {
        fn fill_bytes(&self, dest: &mut [u8]) -> std::result::Result<(), crate::error::RustBoxError> {
            // Use getrandom for tests
            getrandom::getrandom(dest)
                .map_err(|e| crate::error::RustBoxError::Platform(e.to_string()))
        }
    }

    #[test]
    fn test_p256_keypair_generation() {
        let rng = TestRandom;
        let kp = generate_p256_keypair(&rng).unwrap();
        assert_eq!(kp.public_key.len(), 65);
        assert_eq!(kp.public_key[0], 0x04);
        assert!(!kp.private_key.is_empty());
    }

    #[test]
    fn test_p256_ecdh_shared_secret() {
        let rng = TestRandom;
        let kp1 = generate_p256_keypair(&rng).unwrap();
        let kp2 = generate_p256_keypair(&rng).unwrap();

        let secret1 = compute_p256_shared_secret(&kp1.private_key, &kp2.public_key).unwrap();
        let secret2 = compute_p256_shared_secret(&kp2.private_key, &kp1.public_key).unwrap();

        assert_eq!(secret1.len(), 32);
        assert_eq!(secret1, secret2);
    }
}
