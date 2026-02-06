//! Native storage: filesystem blob store and SQLite metadata.

pub mod local_fs;
pub mod sqlite_meta;

pub use local_fs::LocalFs;
pub use sqlite_meta::SqliteMeta;
