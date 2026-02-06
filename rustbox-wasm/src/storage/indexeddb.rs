use async_trait::async_trait;
use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{
    IdbDatabase, IdbFactory, IdbObjectStore, IdbOpenDbRequest, IdbRequest,
    IdbTransactionMode,
};

use rustbox_core::error::RustBoxError;
use rustbox_core::traits::storage::{ContentAddressableStorage, PersistentStorage};

const DB_NAME: &str = "rustbox";
const DB_VERSION: u32 = 1;
const BLOB_STORE: &str = "blobs";
const META_STORE: &str = "metadata";

/// IndexedDB-backed storage for browser WASM.
///
/// Uses two object stores:
/// - "blobs": content-addressable storage keyed by hex-encoded SHA-256 hash
/// - "metadata": key-value storage for arbitrary metadata (salt, vault state, etc.)
pub struct IndexedDbStorage {
    db: IdbDatabase,
}

impl IndexedDbStorage {
    /// Open (or create) the IndexedDB database.
    ///
    /// On first open, creates the "blobs" and "metadata" object stores.
    pub async fn open() -> Result<Self, RustBoxError> {
        let factory = Self::get_idb_factory()?;

        let open_request: IdbOpenDbRequest = factory
            .open_with_u32(DB_NAME, DB_VERSION)
            .map_err(|e| RustBoxError::Storage(format!("IDB open failed: {:?}", e)))?;

        // Set up onupgradeneeded to create object stores
        let on_upgrade = Closure::once(move |event: web_sys::IdbVersionChangeEvent| {
            let target: IdbOpenDbRequest = event
                .target()
                .unwrap()
                .dyn_into()
                .unwrap();
            let db: IdbDatabase = target.result().unwrap().dyn_into().unwrap();

            if !db.object_store_names().contains(BLOB_STORE) {
                db.create_object_store(BLOB_STORE)
                    .expect("failed to create blobs store");
            }
            if !db.object_store_names().contains(META_STORE) {
                db.create_object_store(META_STORE)
                    .expect("failed to create metadata store");
            }
        });
        open_request.set_onupgradeneeded(Some(on_upgrade.as_ref().unchecked_ref()));

        let db_val = Self::await_idb_request(open_request.unchecked_into()).await?;
        // Drop the closure so it doesn't leak
        drop(on_upgrade);

        let db: IdbDatabase = db_val
            .dyn_into()
            .map_err(|_| RustBoxError::Storage("open result is not IdbDatabase".to_string()))?;

        Ok(Self { db })
    }

    /// Get the global IdbFactory.
    fn get_idb_factory() -> Result<IdbFactory, RustBoxError> {
        let window = web_sys::window()
            .ok_or_else(|| RustBoxError::Storage("no window object".to_string()))?;
        window
            .indexed_db()
            .map_err(|e| RustBoxError::Storage(format!("indexed_db() failed: {:?}", e)))?
            .ok_or_else(|| RustBoxError::Storage("indexedDB not available".to_string()))
    }

    /// Wrap an IdbRequest into a Future that resolves with the result.
    async fn await_idb_request(request: IdbRequest) -> Result<JsValue, RustBoxError> {
        let (sender, receiver) = futures_channel::oneshot::channel::<Result<JsValue, RustBoxError>>();

        let sender = std::rc::Rc::new(std::cell::RefCell::new(Some(sender)));
        let sender_ok = sender.clone();
        let sender_err = sender.clone();

        let on_success = Closure::once(move |_event: web_sys::Event| {
            if let Some(tx) = sender_ok.borrow_mut().take() {
                let target: IdbRequest = _event.target().unwrap().dyn_into().unwrap();
                let result = target.result().unwrap_or(JsValue::UNDEFINED);
                let _ = tx.send(Ok(result));
            }
        });

        let on_error = Closure::once(move |_event: web_sys::Event| {
            if let Some(tx) = sender_err.borrow_mut().take() {
                let target: IdbRequest = _event.target().unwrap().dyn_into().unwrap();
                let err = target.error().ok().flatten();
                let msg = err
                    .map(|e| format!("{:?}", e))
                    .unwrap_or_else(|| "unknown IDB error".to_string());
                let _ = tx.send(Err(RustBoxError::Storage(msg)));
            }
        });

        request.set_onsuccess(Some(on_success.as_ref().unchecked_ref()));
        request.set_onerror(Some(on_error.as_ref().unchecked_ref()));

        let result = receiver
            .await
            .map_err(|_| RustBoxError::Storage("IDB request channel cancelled".to_string()))?;

        // Clean up
        request.set_onsuccess(None);
        request.set_onerror(None);
        drop(on_success);
        drop(on_error);

        result
    }

    /// Open a transaction on one object store with the given mode.
    fn transaction(
        &self,
        store_name: &str,
        mode: IdbTransactionMode,
    ) -> Result<IdbObjectStore, RustBoxError> {
        let tx = self
            .db
            .transaction_with_str_and_mode(store_name, mode)
            .map_err(|e| RustBoxError::Storage(format!("transaction failed: {:?}", e)))?;

        tx.object_store(store_name)
            .map_err(|e| RustBoxError::Storage(format!("object_store failed: {:?}", e)))
    }

    /// Convert a 32-byte hash to its hex key string.
    fn hex_key(hash: &[u8; 32]) -> String {
        hex::encode(hash)
    }
}

#[async_trait(?Send)]
impl ContentAddressableStorage for IndexedDbStorage {
    /// Store a blob by its content hash.
    async fn store(&self, hash: &[u8; 32], data: &[u8]) -> Result<(), RustBoxError> {
        let store = self.transaction(BLOB_STORE, IdbTransactionMode::Readwrite)?;
        let key = JsValue::from_str(&Self::hex_key(hash));
        let value = Uint8Array::from(data);

        let request = store
            .put_with_key(&value.into(), &key)
            .map_err(|e| RustBoxError::Storage(format!("put failed: {:?}", e)))?;

        Self::await_idb_request(request).await?;
        Ok(())
    }

    /// Get a blob by its content hash.
    async fn get(&self, hash: &[u8; 32]) -> Result<Vec<u8>, RustBoxError> {
        let store = self.transaction(BLOB_STORE, IdbTransactionMode::Readonly)?;
        let key = JsValue::from_str(&Self::hex_key(hash));

        let request = store
            .get(&key)
            .map_err(|e| RustBoxError::Storage(format!("get failed: {:?}", e)))?;

        let result = Self::await_idb_request(request).await?;

        if result.is_undefined() || result.is_null() {
            return Err(RustBoxError::NotFound(format!(
                "blob not found: {}",
                Self::hex_key(hash)
            )));
        }

        let uint8_array: Uint8Array = result
            .dyn_into()
            .map_err(|_| RustBoxError::Storage("stored value is not Uint8Array".to_string()))?;

        Ok(uint8_array.to_vec())
    }

    /// Check if a blob exists by its content hash.
    async fn exists(&self, hash: &[u8; 32]) -> Result<bool, RustBoxError> {
        let store = self.transaction(BLOB_STORE, IdbTransactionMode::Readonly)?;
        let key = JsValue::from_str(&Self::hex_key(hash));

        let request = store
            .count_with_key(&key)
            .map_err(|e| RustBoxError::Storage(format!("count failed: {:?}", e)))?;

        let result = Self::await_idb_request(request).await?;
        let count = result.as_f64().unwrap_or(0.0);
        Ok(count > 0.0)
    }

    /// List all blob hashes.
    async fn list_hashes(&self) -> Result<Vec<[u8; 32]>, RustBoxError> {
        let store = self.transaction(BLOB_STORE, IdbTransactionMode::Readonly)?;

        let request = store
            .get_all_keys()
            .map_err(|e| RustBoxError::Storage(format!("getAllKeys failed: {:?}", e)))?;

        let result = Self::await_idb_request(request).await?;
        let keys: Array = result
            .dyn_into()
            .map_err(|_| RustBoxError::Storage("keys is not an Array".to_string()))?;

        let mut hashes = Vec::new();
        for i in 0..keys.length() {
            let key_val = keys.get(i);
            if let Some(hex_str) = key_val.as_string() {
                if let Ok(bytes) = hex::decode(&hex_str) {
                    if bytes.len() == 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&bytes);
                        hashes.push(hash);
                    }
                }
            }
        }

        Ok(hashes)
    }

    /// Delete a blob by its content hash.
    async fn delete(&self, hash: &[u8; 32]) -> Result<(), RustBoxError> {
        let store = self.transaction(BLOB_STORE, IdbTransactionMode::Readwrite)?;
        let key = JsValue::from_str(&Self::hex_key(hash));

        let request = store
            .delete(&key)
            .map_err(|e| RustBoxError::Storage(format!("delete failed: {:?}", e)))?;

        Self::await_idb_request(request).await?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PersistentStorage for IndexedDbStorage {
    /// Set a key-value pair in the metadata store.
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), RustBoxError> {
        let store = self.transaction(META_STORE, IdbTransactionMode::Readwrite)?;
        let js_key = JsValue::from_str(key);
        let js_value = Uint8Array::from(value);

        let request = store
            .put_with_key(&js_value.into(), &js_key)
            .map_err(|e| RustBoxError::Storage(format!("put failed: {:?}", e)))?;

        Self::await_idb_request(request).await?;
        Ok(())
    }

    /// Get a value by key from the metadata store.
    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, RustBoxError> {
        let store = self.transaction(META_STORE, IdbTransactionMode::Readonly)?;
        let js_key = JsValue::from_str(key);

        let request = store
            .get(&js_key)
            .map_err(|e| RustBoxError::Storage(format!("get failed: {:?}", e)))?;

        let result = Self::await_idb_request(request).await?;

        if result.is_undefined() || result.is_null() {
            return Ok(None);
        }

        let uint8_array: Uint8Array = result
            .dyn_into()
            .map_err(|_| RustBoxError::Storage("stored value is not Uint8Array".to_string()))?;

        Ok(Some(uint8_array.to_vec()))
    }

    /// Delete a key from the metadata store.
    async fn delete(&self, key: &str) -> Result<(), RustBoxError> {
        let store = self.transaction(META_STORE, IdbTransactionMode::Readwrite)?;
        let js_key = JsValue::from_str(key);

        let request = store
            .delete(&js_key)
            .map_err(|e| RustBoxError::Storage(format!("delete failed: {:?}", e)))?;

        Self::await_idb_request(request).await?;
        Ok(())
    }

    /// List all keys in the metadata store that start with the given prefix.
    async fn list_keys(&self, prefix: &str) -> Result<Vec<String>, RustBoxError> {
        let store = self.transaction(META_STORE, IdbTransactionMode::Readonly)?;

        let request = store
            .get_all_keys()
            .map_err(|e| RustBoxError::Storage(format!("getAllKeys failed: {:?}", e)))?;

        let result = Self::await_idb_request(request).await?;
        let keys: Array = result
            .dyn_into()
            .map_err(|_| RustBoxError::Storage("keys is not an Array".to_string()))?;

        let mut matching = Vec::new();
        for i in 0..keys.length() {
            let key_val = keys.get(i);
            if let Some(key_str) = key_val.as_string() {
                if key_str.starts_with(prefix) {
                    matching.push(key_str);
                }
            }
        }

        Ok(matching)
    }
}
