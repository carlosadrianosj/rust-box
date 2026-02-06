//! Browser transport: HTTP `fetch()` against the Axum REST API.

pub mod fetch;

pub use fetch::FetchTransport;
