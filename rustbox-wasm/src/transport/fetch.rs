use async_trait::async_trait;
use js_sys::{ArrayBuffer, JSON, Reflect, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::JsFuture;
use web_sys::{Request, RequestInit, RequestMode, Response};

use rustbox_core::error::RustBoxError;
use rustbox_core::traits::transport::Transport;

/// Fetch API-based HTTP transport for browser WASM.
///
/// Communicates with the RustBox server via standard HTTP endpoints.
pub struct FetchTransport {
    base_url: String,
    user_id: Option<String>,
}

impl FetchTransport {
    pub fn new(base_url: &str) -> Self {
        // Strip trailing slash for consistent URL construction
        let base = base_url.trim_end_matches('/').to_string();
        Self { base_url: base, user_id: None }
    }

    /// Set the user_id for authenticated requests.
    pub fn set_user_id(&mut self, user_id: &str) {
        self.user_id = Some(user_id.to_string());
    }

    /// Get the user_id query string fragment (e.g. "?user_id=xxx" or "&user_id=xxx").
    fn user_id_query(&self, prefix: &str) -> String {
        match &self.user_id {
            Some(id) => format!("{}user_id={}", prefix, id),
            None => String::new(),
        }
    }

    /// Get the browser's global `window` object for calling fetch.
    fn window() -> Result<web_sys::Window, RustBoxError> {
        web_sys::window().ok_or_else(|| {
            RustBoxError::Platform("No global `window` object found".to_string())
        })
    }

    /// Convert a hex string from a 32-byte hash.
    fn hex_hash(hash: &[u8; 32]) -> String {
        hex::encode(hash)
    }

    /// Perform a fetch request and return the Response.
    async fn do_fetch(request: &Request) -> Result<Response, RustBoxError> {
        let window = Self::window()?;
        let resp_value = JsFuture::from(window.fetch_with_request(request))
            .await
            .map_err(|e| RustBoxError::Transport(format!("fetch failed: {:?}", e)))?;

        let resp: Response = resp_value
            .dyn_into()
            .map_err(|_| RustBoxError::Transport("response is not a Response".to_string()))?;

        Ok(resp)
    }

    /// Read the full body of a Response as bytes.
    async fn read_body_bytes(resp: &Response) -> Result<Vec<u8>, RustBoxError> {
        let array_buffer_promise = resp
            .array_buffer()
            .map_err(|e| RustBoxError::Transport(format!("array_buffer() failed: {:?}", e)))?;

        let array_buffer: ArrayBuffer = JsFuture::from(array_buffer_promise)
            .await
            .map_err(|e| RustBoxError::Transport(format!("reading body failed: {:?}", e)))?
            .dyn_into()
            .map_err(|_| RustBoxError::Transport("body is not an ArrayBuffer".to_string()))?;

        let uint8_array = Uint8Array::new(&array_buffer);
        Ok(uint8_array.to_vec())
    }

    /// Read the body as text and parse as JSON, returning the JsValue.
    async fn read_body_json(resp: &Response) -> Result<JsValue, RustBoxError> {
        let text_promise = resp
            .text()
            .map_err(|e| RustBoxError::Transport(format!("text() failed: {:?}", e)))?;

        let text_val = JsFuture::from(text_promise)
            .await
            .map_err(|e| RustBoxError::Transport(format!("reading text failed: {:?}", e)))?;

        let text = text_val
            .as_string()
            .ok_or_else(|| RustBoxError::Transport("body text is not a string".to_string()))?;

        JSON::parse(&text)
            .map_err(|e| RustBoxError::Transport(format!("JSON parse failed: {:?}", e)))
    }

    /// Build a request with the given method, URL, optional body and content-type.
    fn build_request(
        method: &str,
        url: &str,
        body: Option<&[u8]>,
        content_type: Option<&str>,
    ) -> Result<Request, RustBoxError> {
        let opts = RequestInit::new();
        opts.set_method(method);
        opts.set_mode(RequestMode::Cors);

        if let Some(data) = body {
            let uint8_array = Uint8Array::from(data);
            opts.set_body(&uint8_array.into());
        }

        let request = Request::new_with_str_and_init(url, &opts)
            .map_err(|e| RustBoxError::Transport(format!("Request creation failed: {:?}", e)))?;

        if let Some(ct) = content_type {
            request
                .headers()
                .set("Content-Type", ct)
                .map_err(|e| {
                    RustBoxError::Transport(format!("set Content-Type failed: {:?}", e))
                })?;
        }

        Ok(request)
    }

    /// Check that the response status is in the expected range.
    fn check_status(resp: &Response, expected_min: u16, expected_max: u16) -> Result<(), RustBoxError> {
        let status = resp.status();
        if status >= expected_min && status <= expected_max {
            Ok(())
        } else {
            Err(RustBoxError::Transport(format!(
                "unexpected status {}: expected {}-{}",
                status, expected_min, expected_max
            )))
        }
    }
}

impl FetchTransport {
    /// GET /api/auth/salt?username={username}
    /// Returns Some(salt_bytes) or None if user not found.
    pub async fn get_salt(&self, username: &str) -> Result<Option<Vec<u8>>, RustBoxError> {
        let url = format!("{}/api/auth/salt?username={}", self.base_url, username);
        let request = Self::build_request("GET", &url, None, None)?;
        let resp = Self::do_fetch(&request).await?;

        if resp.status() == 404 {
            return Ok(None);
        }
        Self::check_status(&resp, 200, 200)?;

        let json = Self::read_body_json(&resp).await?;
        let salt_hex = Reflect::get(&json, &JsValue::from_str("salt_hex"))
            .ok()
            .and_then(|v| v.as_string());

        match salt_hex {
            Some(hex_str) => {
                let bytes = hex::decode(&hex_str)
                    .map_err(|e| RustBoxError::Transport(format!("invalid salt hex: {e}")))?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    /// GET /api/manifests/list?user_id={uuid}
    /// Returns JSON string of manifest summaries.
    pub async fn list_manifests(&self, user_id: &str) -> Result<String, RustBoxError> {
        let url = format!("{}/api/manifests/list?user_id={}", self.base_url, user_id);
        let request = Self::build_request("GET", &url, None, None)?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 200)?;

        let text_promise = resp.text()
            .map_err(|e| RustBoxError::Transport(format!("text() failed: {:?}", e)))?;
        let text_val = JsFuture::from(text_promise).await
            .map_err(|e| RustBoxError::Transport(format!("reading text failed: {:?}", e)))?;
        let text = text_val.as_string()
            .ok_or_else(|| RustBoxError::Transport("body is not a string".to_string()))?;

        Ok(text)
    }

    /// GET /api/db/overview?user_id={uuid}
    pub async fn get_db_overview(&self, user_id: &str) -> Result<String, RustBoxError> {
        let url = format!("{}/api/db/overview?user_id={}", self.base_url, user_id);
        let request = Self::build_request("GET", &url, None, None)?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 200)?;

        let text_promise = resp.text()
            .map_err(|e| RustBoxError::Transport(format!("text() failed: {:?}", e)))?;
        let text_val = JsFuture::from(text_promise).await
            .map_err(|e| RustBoxError::Transport(format!("reading text failed: {:?}", e)))?;
        let text = text_val.as_string()
            .ok_or_else(|| RustBoxError::Transport("body is not a string".to_string()))?;

        Ok(text)
    }

    /// DELETE /api/manifests/{id}?user_id={uuid}
    pub async fn delete_manifest(&self, manifest_id: &str, user_id: &str) -> Result<(), RustBoxError> {
        let url = format!("{}/api/manifests/{}?user_id={}", self.base_url, manifest_id, user_id);
        let request = Self::build_request("DELETE", &url, None, None)?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 200)?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl Transport for FetchTransport {
    /// Upload an encrypted chunk: PUT /api/chunks/{hex_hash}?user_id={uuid}
    async fn upload_chunk(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError> {
        let url = format!("{}/api/chunks/{}{}", self.base_url, Self::hex_hash(hash), self.user_id_query("?"));
        let request = Self::build_request("PUT", &url, Some(data), Some("application/octet-stream"))?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 201)?;
        Ok(())
    }

    /// Download an encrypted chunk: GET /api/chunks/{hex_hash}
    async fn download_chunk(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError> {
        let url = format!("{}/api/chunks/{}", self.base_url, Self::hex_hash(hash));
        let request = Self::build_request("GET", &url, None, None)?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 200)?;
        Self::read_body_bytes(&resp).await
    }

    /// Upload an encrypted manifest: POST /api/manifests?user_id={uuid}
    /// Returns the manifest ID from the JSON response: { "id": "..." }
    async fn upload_manifest(&self, data: &[u8]) -> Result<String, RustBoxError> {
        let url = format!("{}/api/manifests{}", self.base_url, self.user_id_query("?"));
        let request = Self::build_request("POST", &url, Some(data), Some("application/octet-stream"))?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 201)?;

        let json = Self::read_body_json(&resp).await?;
        let id = Reflect::get(&json, &JsValue::from_str("id"))
            .map_err(|e| RustBoxError::Transport(format!("missing 'id' in response: {:?}", e)))?
            .as_string()
            .ok_or_else(|| RustBoxError::Transport("'id' is not a string".to_string()))?;

        Ok(id)
    }

    /// Download an encrypted manifest: GET /api/manifests/{id}
    async fn download_manifest(&self, id: &str) -> Result<Vec<u8>, RustBoxError> {
        let url = format!("{}/api/manifests/{}", self.base_url, id);
        let request = Self::build_request("GET", &url, None, None)?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 200)?;
        Self::read_body_bytes(&resp).await
    }

    /// Get the server's Merkle root: GET /api/sync/root?user_id={uuid}
    /// Response: { "merkle_root": "hex_encoded_32_bytes" | null }
    async fn get_merkle_root(&self) -> Result<[u8; 32], RustBoxError> {
        let url = format!("{}/api/sync/root{}", self.base_url, self.user_id_query("?"));
        let request = Self::build_request("GET", &url, None, None)?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 200)?;

        let json = Self::read_body_json(&resp).await?;
        let root_val = Reflect::get(&json, &JsValue::from_str("merkle_root"))
            .map_err(|e| RustBoxError::Transport(format!("missing 'merkle_root': {:?}", e)))?;

        // Handle null merkle_root (empty server)
        if root_val.is_null() || root_val.is_undefined() {
            return Ok([0u8; 32]);
        }

        let root_hex = root_val
            .as_string()
            .ok_or_else(|| RustBoxError::Transport("'merkle_root' is not a string".to_string()))?;

        let root_bytes = hex::decode(&root_hex)
            .map_err(|e| RustBoxError::Transport(format!("invalid hex root: {}", e)))?;

        if root_bytes.len() != 32 {
            return Err(RustBoxError::Transport(format!(
                "root hash wrong length: expected 32, got {}",
                root_bytes.len()
            )));
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&root_bytes);
        Ok(root)
    }

    /// Get missing chunks by posting local root: POST /api/sync/diff
    /// Request: { "local_root": "hex_encoded", "user_id": "..." }
    /// Response: { "missing_hashes": ["hex1", "hex2", ...] }
    async fn get_merkle_diff(&self, local_root: &[u8; 32]) -> Result<Vec<[u8; 32]>, RustBoxError> {
        let url = format!("{}/api/sync/diff", self.base_url);
        let user_id_field = match &self.user_id {
            Some(id) => format!(r#","user_id":"{}""#, id),
            None => String::new(),
        };
        let body_str = format!(r#"{{"local_root":"{}"{}}}"#, hex::encode(local_root), user_id_field);
        let body_bytes = body_str.as_bytes();
        let request = Self::build_request("POST", &url, Some(body_bytes), Some("application/json"))?;
        let resp = Self::do_fetch(&request).await?;
        Self::check_status(&resp, 200, 200)?;

        let json = Self::read_body_json(&resp).await?;
        let missing_val = Reflect::get(&json, &JsValue::from_str("missing_hashes"))
            .map_err(|e| RustBoxError::Transport(format!("missing 'missing_hashes': {:?}", e)))?;

        let missing_array: js_sys::Array = missing_val
            .dyn_into()
            .map_err(|_| RustBoxError::Transport("'missing' is not an array".to_string()))?;

        let mut result = Vec::new();
        for i in 0..missing_array.length() {
            let hex_val = missing_array.get(i);
            let hex_str = hex_val
                .as_string()
                .ok_or_else(|| RustBoxError::Transport("missing entry is not a string".to_string()))?;

            let bytes = hex::decode(&hex_str)
                .map_err(|e| RustBoxError::Transport(format!("invalid hex: {}", e)))?;

            if bytes.len() != 32 {
                return Err(RustBoxError::Transport(format!(
                    "hash wrong length: expected 32, got {}",
                    bytes.len()
                )));
            }

            let mut hash = [0u8; 32];
            hash.copy_from_slice(&bytes);
            result.push(hash);
        }

        Ok(result)
    }
}
