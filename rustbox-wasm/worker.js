// RustBox Crypto Web Worker
//
// Offloads chunk encryption/decryption to a separate thread so the main
// thread stays responsive during large file operations.
//
// Messages from main thread:
//   { type: "encrypt", id: number, file_enc_key: Uint8Array, chunk_index: number, plaintext: Uint8Array }
//   { type: "decrypt", id: number, file_enc_key: Uint8Array, chunk_index: number, encrypted_data: Uint8Array, nonce: Uint8Array }
//
// Messages to main thread:
//   { type: "result", id: number, ok: true, data: { hash, encrypted_data, nonce, index } }  (encrypt)
//   { type: "result", id: number, ok: true, data: Uint8Array }                               (decrypt)
//   { type: "result", id: number, ok: false, error: string }

importScripts('./pkg/rustbox_wasm.js');

let wasmReady = false;
let pendingMessages = [];

async function initWasm() {
    try {
        await wasm_bindgen('./pkg/rustbox_wasm_bg.wasm');
        wasmReady = true;
        // Process any messages that arrived before WASM was ready
        for (const msg of pendingMessages) {
            await handleMessage(msg);
        }
        pendingMessages = [];
    } catch (err) {
        console.error('RustBox Worker: WASM init failed:', err);
    }
}

async function handleMessage(data) {
    const { type, id } = data;

    try {
        if (type === 'encrypt') {
            const { file_enc_key, chunk_index, plaintext } = data;
            const result = wasm_bindgen.encrypt_chunk_worker(
                new Uint8Array(file_enc_key),
                chunk_index,
                new Uint8Array(plaintext)
            );
            self.postMessage({
                type: 'result',
                id: id,
                ok: true,
                data: {
                    hash: result.hash,
                    encrypted_data: result.encrypted_data,
                    nonce: result.nonce,
                    index: result.index
                }
            });
        } else if (type === 'decrypt') {
            const { file_enc_key, chunk_index, encrypted_data, nonce } = data;
            const plaintext = wasm_bindgen.decrypt_chunk_worker(
                new Uint8Array(file_enc_key),
                chunk_index,
                new Uint8Array(encrypted_data),
                new Uint8Array(nonce)
            );
            self.postMessage({
                type: 'result',
                id: id,
                ok: true,
                data: plaintext
            });
        } else {
            self.postMessage({
                type: 'result',
                id: id,
                ok: false,
                error: 'unknown message type: ' + type
            });
        }
    } catch (err) {
        self.postMessage({
            type: 'result',
            id: id,
            ok: false,
            error: err.toString()
        });
    }
}

self.onmessage = async function(e) {
    if (!wasmReady) {
        pendingMessages.push(e.data);
        return;
    }
    await handleMessage(e.data);
};

// Initialize WASM on worker startup
initWasm();
