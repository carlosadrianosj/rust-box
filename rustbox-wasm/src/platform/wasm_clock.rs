use rustbox_core::error::RustBoxError;
use rustbox_core::traits::clock::Clock;

/// WASM-compatible clock using `js_sys::Date::now()`.
///
/// Returns milliseconds since the Unix epoch as an f64,
/// which we convert to u64.
pub struct WasmClock;

impl WasmClock {
    pub fn new() -> Self {
        Self
    }
}

impl Default for WasmClock {
    fn default() -> Self {
        Self::new()
    }
}

impl Clock for WasmClock {
    fn now_secs(&self) -> Result<u64, RustBoxError> {
        let ms = js_sys::Date::now();
        Ok((ms / 1000.0) as u64)
    }

    fn now_millis(&self) -> Result<u64, RustBoxError> {
        let ms = js_sys::Date::now();
        Ok(ms as u64)
    }
}
