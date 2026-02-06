use wasm_bindgen::prelude::*;

use rustbox_core::chunking::pipeline;
use rustbox_core::constants::XCHACHA20_NONCE_LEN;
use crate::platform::WasmRandom;

/// Encrypt a chunk in a Web Worker context.
///
/// Called from the worker thread with the file encryption key, chunk index,
/// and plaintext data. Returns a JsValue containing:
/// {
///   hash: Uint8Array(32),
///   encrypted_data: Uint8Array,
///   nonce: Uint8Array(24),
///   index: u32
/// }
#[wasm_bindgen]
pub fn encrypt_chunk_worker(
    file_enc_key: &[u8],
    chunk_index: u32,
    plaintext: &[u8],
) -> Result<JsValue, JsValue> {
    if file_enc_key.len() != 32 {
        return Err(JsValue::from_str("file_enc_key must be 32 bytes"));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(file_enc_key);

    let rng = WasmRandom::new();
    let encrypted = pipeline::encrypt_chunk(&key, chunk_index, plaintext, &rng)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    let result = js_sys::Object::new();

    let hash_array = js_sys::Uint8Array::from(&encrypted.hash[..]);
    js_sys::Reflect::set(&result, &JsValue::from_str("hash"), &hash_array.into())
        .map_err(|e| JsValue::from_str(&format!("set hash failed: {:?}", e)))?;

    let data_array = js_sys::Uint8Array::from(&encrypted.encrypted_data[..]);
    js_sys::Reflect::set(&result, &JsValue::from_str("encrypted_data"), &data_array.into())
        .map_err(|e| JsValue::from_str(&format!("set data failed: {:?}", e)))?;

    let nonce_array = js_sys::Uint8Array::from(&encrypted.nonce[..]);
    js_sys::Reflect::set(&result, &JsValue::from_str("nonce"), &nonce_array.into())
        .map_err(|e| JsValue::from_str(&format!("set nonce failed: {:?}", e)))?;

    js_sys::Reflect::set(
        &result,
        &JsValue::from_str("index"),
        &JsValue::from(chunk_index),
    )
    .map_err(|e| JsValue::from_str(&format!("set index failed: {:?}", e)))?;

    Ok(result.into())
}

/// Decrypt a chunk in a Web Worker context.
///
/// Called from the worker thread with the file encryption key, chunk index,
/// encrypted data, and nonce. Returns the decrypted plaintext as Uint8Array.
#[wasm_bindgen]
pub fn decrypt_chunk_worker(
    file_enc_key: &[u8],
    chunk_index: u32,
    encrypted_data: &[u8],
    nonce: &[u8],
) -> Result<Vec<u8>, JsValue> {
    if file_enc_key.len() != 32 {
        return Err(JsValue::from_str("file_enc_key must be 32 bytes"));
    }
    if nonce.len() != XCHACHA20_NONCE_LEN {
        return Err(JsValue::from_str(&format!(
            "nonce must be {} bytes",
            XCHACHA20_NONCE_LEN
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(file_enc_key);

    let mut nonce_arr = [0u8; XCHACHA20_NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);

    let plaintext = pipeline::decrypt_chunk(&key, chunk_index, encrypted_data, &nonce_arr)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;

    Ok(plaintext)
}
