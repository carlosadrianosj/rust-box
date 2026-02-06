use crate::error::RustBoxError;

/// Cryptographically secure random byte generator (OS CSPRNG on native, `crypto.getRandomValues` on WASM).
pub trait SecureRandom {
    /// Fill `dest` with cryptographically secure random bytes.
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RustBoxError>;

    /// Allocate and return `len` random bytes.
    fn random_bytes(&self, len: usize) -> Result<Vec<u8>, RustBoxError> {
        let mut buf = vec![0u8; len];
        self.fill_bytes(&mut buf)?;
        Ok(buf)
    }
}
