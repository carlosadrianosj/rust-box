use crate::error::RustBoxError;

pub trait SecureRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RustBoxError>;

    fn random_bytes(&self, len: usize) -> Result<Vec<u8>, RustBoxError> {
        let mut buf = vec![0u8; len];
        self.fill_bytes(&mut buf)?;
        Ok(buf)
    }
}
