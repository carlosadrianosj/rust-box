use rustbox_core::error::RustBoxError;
use rustbox_core::traits::random::SecureRandom;

/// WASM-compatible secure random number generator.
///
/// Uses the `getrandom` crate with the "js" feature, which delegates
/// to `crypto.getRandomValues()` in the browser or Node.js.
pub struct WasmRandom;

impl WasmRandom {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WasmRandom {
    fn default() -> Self {
        Self::new()
    }
}

impl SecureRandom for WasmRandom {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RustBoxError> {
        getrandom::getrandom(dest)
            .map_err(|e| RustBoxError::Platform(format!("getrandom failed: {}", e)))
    }
}
