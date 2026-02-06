use rustbox_core::error::RustBoxError;
use rustbox_core::traits::random::SecureRandom;

/// Native SecureRandom implementation using the OS CSPRNG via getrandom.
pub struct NativeRandom;

impl NativeRandom {
    pub fn new() -> Self {
        Self
    }
}

impl SecureRandom for NativeRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RustBoxError> {
        getrandom::getrandom(dest)
            .map_err(|e| RustBoxError::Platform(format!("getrandom failed: {e}")))
    }
}
