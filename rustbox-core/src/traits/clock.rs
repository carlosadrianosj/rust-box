use crate::error::RustBoxError;

pub trait Clock {
    fn now_secs(&self) -> Result<u64, RustBoxError>;
    fn now_millis(&self) -> Result<u64, RustBoxError>;
}
