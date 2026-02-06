use crate::error::RustBoxError;

/// Wall-clock time source (system clock on native, `Date.now()` on WASM).
pub trait Clock {
    /// Current Unix timestamp in seconds.
    fn now_secs(&self) -> Result<u64, RustBoxError>;
    /// Current Unix timestamp in milliseconds.
    fn now_millis(&self) -> Result<u64, RustBoxError>;
}
