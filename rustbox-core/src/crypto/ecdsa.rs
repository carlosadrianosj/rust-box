use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use p256::EncodedPoint;
use p256::PublicKey;
use elliptic_curve::sec1::FromEncodedPoint;

use super::{CryptoError, Result};

pub fn ecdsa_p256_verify(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<()> {
    let encoded_point = EncodedPoint::from_bytes(public_key)
        .map_err(|e| CryptoError::EcdsaVerify(format!("invalid public key encoding: {e}")))?;

    let pub_key = PublicKey::from_encoded_point(&encoded_point);
    if pub_key.is_none().into() {
        return Err(CryptoError::EcdsaVerify("invalid public key point".into()));
    }
    let pub_key = pub_key.unwrap();

    let verifying_key = VerifyingKey::from(pub_key);

    let sig = Signature::from_der(signature)
        .map_err(|e| CryptoError::EcdsaVerify(format!("invalid signature encoding: {e}")))?;

    verifying_key
        .verify(message, &sig)
        .map_err(|e| CryptoError::EcdsaVerify(format!("verification failed: {e}")))
}

pub fn ecdsa_p256_sign(
    private_key: &[u8],
    message: &[u8],
) -> Result<Vec<u8>> {
    use p256::ecdsa::{SigningKey, signature::Signer};

    let signing_key = SigningKey::from_bytes(private_key.into())
        .map_err(|e| CryptoError::EcdsaVerify(format!("invalid signing key: {e}")))?;

    let signature: Signature = signing_key.sign(message);
    Ok(signature.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::SigningKey;

    #[test]
    fn test_ecdsa_sign_and_verify() {
        let mut rng_bytes = [0u8; 32];
        getrandom::getrandom(&mut rng_bytes).unwrap();
        let signing_key = SigningKey::from_bytes((&rng_bytes).into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"Hello RustBox CertificateVerify!";

        let signature = ecdsa_p256_sign(
            signing_key.to_bytes().as_slice(),
            message,
        )
        .unwrap();

        let pub_key_bytes = EncodedPoint::from(verifying_key);

        ecdsa_p256_verify(pub_key_bytes.as_bytes(), message, &signature).unwrap();
    }

    #[test]
    fn test_ecdsa_verify_wrong_message() {
        let mut rng_bytes = [0u8; 32];
        getrandom::getrandom(&mut rng_bytes).unwrap();
        let signing_key = SigningKey::from_bytes((&rng_bytes).into()).unwrap();
        let verifying_key = signing_key.verifying_key();

        let message = b"correct message";
        let signature = ecdsa_p256_sign(
            signing_key.to_bytes().as_slice(),
            message,
        )
        .unwrap();

        let pub_key_bytes = EncodedPoint::from(verifying_key);
        let result = ecdsa_p256_verify(pub_key_bytes.as_bytes(), b"wrong message", &signature);
        assert!(result.is_err());
    }
}
