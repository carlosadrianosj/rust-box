# Transport Layer

RustBox supports two transport protocols: QUIC and HTTP. The core crate defines
a `Transport` trait; each client implements it using the appropriate protocol for
its runtime.

## Transport Trait

From `rustbox-core/src/traits/transport.rs`:

```rust
#[async_trait(?Send)]
pub trait Transport {
    async fn upload_chunk(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError>;
    async fn download_chunk(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError>;
    async fn upload_manifest(&self, data: &[u8]) -> Result<String, RustBoxError>;
    async fn download_manifest(&self, id: &str) -> Result<Vec<u8>, RustBoxError>;
    async fn get_merkle_root(&self) -> Result<[u8; 32], RustBoxError>;
    async fn get_merkle_diff(&self, local_root: &[u8; 32]) -> Result<Vec<[u8; 32]>, RustBoxError>;
}
```

The `?Send` bound is deliberate: WASM runs on a single thread and cannot satisfy
`Send`. By using `#[async_trait(?Send)]`, the same trait definition compiles
under both Tokio (multi-threaded) and WASM (single-threaded) runtimes.

## QUIC Transport (CLI)

The CLI client uses Quinn (a pure-Rust QUIC implementation) to communicate with
the server over UDP on port 4433.

### Protocol

QUIC provides multiplexed streams over a single UDP socket. Each RustBox
operation opens a new bidirectional stream:

```
Client                                Server (:4433)
  |                                      |
  |  QUIC handshake (TLS 1.3)           |
  |  <================================> |
  |                                      |
  |  Stream 1: upload chunk              |
  |  [op_code (1B) | hash (32B) | data]  |
  |  ================================>   |
  |  [status (1B)]                        |
  |  <================================   |
  |                                      |
  |  Stream 2: download chunk            |
  |  [op_code (1B) | hash (32B)]         |
  |  ================================>   |
  |  [status (1B) | data]                |
  |  <================================   |
  |                                      |
  |  Stream 3: upload manifest           |
  |  [op_code (1B) | data]               |
  |  ================================>   |
  |  [status (1B) | id_len (4B) | id]    |
  |  <================================   |
  +--------------------------------------+
```

### Advantages over HTTP

| Property           | QUIC               | HTTP                |
|--------------------|--------------------|---------------------|
| Connection setup   | 1-RTT (0-RTT PSK)  | TCP + TLS handshake |
| Multiplexing       | Native streams     | HTTP/1.1 sequential |
| Head-of-line block | Per-stream only    | Per-connection      |
| Binary framing     | Direct             | Base64 or multipart |

For bulk file transfers, QUIC's multiplexed streams allow multiple chunks to
upload simultaneously without head-of-line blocking. Benchmarks show 44 MB/s
upload and 75 MB/s download throughput for a 309 MB file over localhost.

### Self-Signed Certificates

The server generates a self-signed certificate at startup using `rcgen`. The CLI
client trusts this certificate by adding it to a custom `rustls` certificate
store. This is acceptable for a proof-of-concept; production deployments would
use a proper CA-signed certificate.

## HTTP Transport (WASM)

The browser client uses the Fetch API to communicate with the server's Axum HTTP
endpoints on port 8443.

### API Endpoints

| Method | Path                     | Body              | Response              |
|--------|--------------------------|-------------------|-----------------------|
| POST   | /register                | JSON credentials  | JSON status           |
| POST   | /login                   | JSON credentials  | JSON token + salt     |
| POST   | /upload/chunk            | Binary chunk data | JSON status           |
| GET    | /download/chunk/:hash    | (none)            | Binary chunk data     |
| POST   | /upload/manifest         | Binary envelope   | JSON manifest ID      |
| GET    | /manifest/:id            | (none)            | Binary envelope       |
| GET    | /merkle/root             | (none)            | JSON root hash        |
| POST   | /merkle/diff             | JSON local root   | JSON leaf hash list   |
| GET    | /manifests               | (none)            | JSON manifest list    |
| DELETE | /manifest/:id            | (none)            | JSON status           |
| GET    | /status                  | (none)            | JSON vault status     |
| GET    | /health                  | (none)            | JSON server health    |

### FetchTransport

The `FetchTransport` struct wraps the browser Fetch API through `wasm-bindgen`:

```
Browser JS  -->  wasm-bindgen  -->  FetchTransport  -->  Transport trait
```

All requests include an authorization token obtained during login. Binary data
(chunks, manifests) is sent and received as raw `ArrayBuffer` without Base64
encoding to minimize overhead.

## Server Dispatch

The server handles both protocols simultaneously:

```
+----------------------------------------------------------+
|                     rustbox-server                        |
|                                                           |
|   Axum (Tokio)          Quinn (Tokio)                     |
|   :8443 TCP             :4433 UDP                         |
|   HTTP REST API          QUIC binary protocol             |
|                                                           |
|   Both share:                                             |
|     AppState { pool, sessions, ecdh_keys, ecdsa_keys }   |
|     PostgreSQL connection pool (sqlx)                     |
|     DashMap session store                                 |
+----------------------------------------------------------+
```

Both listeners run concurrently under the same Tokio runtime. They share the
`AppState` struct via `Arc`, giving both protocols access to the same database
pool and session store.

### CRISP Integration

The QUIC transport optionally wraps its payload in CRISP records for end-to-end
encryption. When CRISP is active:

```
Client                             Server
  |                                   |
  |  QUIC stream                      |
  |  [CRISP ClientHello record]       |
  |  ==============================>  |
  |                                   |
  |  [CRISP ServerHello + records]    |
  |  <==============================  |
  |                                   |
  |  Session established              |
  |                                   |
  |  [CRISP encrypted app data]      |
  |  ==============================>  |
  |  <==============================  |
  +-----------------------------------+
```

The CRISP handshake runs inside QUIC streams, providing an additional layer of
application-level encryption beyond the QUIC/TLS transport encryption.
