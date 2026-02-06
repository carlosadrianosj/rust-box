//! Browser platform: `crypto.getRandomValues()` RNG and `Date.now()` clock.

pub mod wasm_random;
pub mod wasm_clock;

pub use wasm_random::WasmRandom;
pub use wasm_clock::WasmClock;
