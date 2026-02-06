use std::time::SystemTime;

use rustbox_core::error::RustBoxError;
use rustbox_core::traits::clock::Clock;

/// Native Clock implementation using std::time::SystemTime.
pub struct NativeClock;

impl NativeClock {
    pub fn new() -> Self {
        Self
    }
}

impl Clock for NativeClock {
    fn now_secs(&self) -> Result<u64, RustBoxError> {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| RustBoxError::Platform(format!("SystemTime error: {e}")))
    }

    fn now_millis(&self) -> Result<u64, RustBoxError> {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .map_err(|e| RustBoxError::Platform(format!("SystemTime error: {e}")))
    }
}
