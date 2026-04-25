//! WebAssembly bindings for Lupine post-quantum cryptography.
//!
//! This crate provides a thin `wasm-bindgen` wrapper around Lupine's
//! [`easy`](lupine::easy) API, exposing key generation, encryption, decryption,
//! signing, and verification to JavaScript (browser and Node.js).
//!
//! # JavaScript usage
//!
//! ```javascript
//! import init, { generateKeys, encrypt, decrypt, sign, verify } from '@lupine/pqc';
//!
//! await init();
//!
//! const keys = generateKeys();
//! const sealed = encrypt(keys.kemPublicKey, new TextEncoder().encode("secret"));
//! const plain = decrypt(keys.kemSecretKey, sealed);
//! console.log(new TextDecoder().decode(plain)); // "secret"
//!
//! const sig = sign(keys.signSecretKey, new TextEncoder().encode("message"));
//! const valid = verify(keys.signPublicKey, new TextEncoder().encode("message"), sig);
//! console.assert(valid === true);
//! ```
//!
//! # RNG
//!
//! Browser environments use `crypto.getRandomValues()` for all randomness via
//! the `getrandom` crate's `js` feature. WASI environments use `random_get`.
//!
//! @decision DEC-WASM-001
//! @title Thin wrapper over easy API with struct-based key return
//! @status accepted
//! @rationale The WASM bindings are intentionally minimal — a thin translation
//!   layer between Lupine's easy API and JavaScript. Key material is returned
//!   as a `Keys` struct with getter methods that return `Vec<u8>` (which
//!   wasm-bindgen converts to `Uint8Array`). This avoids serde-wasm-bindgen
//!   complexity for the common case while keeping the JS API ergonomic with
//!   camelCase property names. Internal functions use `Result<_, String>` so
//!   native tests can exercise the same logic without wasm-bindgen's JsError
//!   (which panics on non-wasm targets).

use lupine_kem::hybrid::{HybridKemPublicKey768, HybridKemSecretKey768};
use lupine_sign::hybrid::{HybridSigningKey65, HybridVerifyingKey65};
use wasm_bindgen::prelude::*;

// ── Keys struct ──────────────────────────────────────────────────────────────

/// A complete PQC keypair for encryption and signing.
///
/// Returned by `generateKeys`. Access individual keys via the getter
/// properties: `kemPublicKey`, `kemSecretKey`, `signPublicKey`, `signSecretKey`.
/// Each returns a `Uint8Array` in JavaScript.
#[wasm_bindgen]
pub struct Keys {
    kem_public_key: Vec<u8>,
    kem_secret_key: Vec<u8>,
    sign_public_key: Vec<u8>,
    sign_secret_key: Vec<u8>,
}

#[wasm_bindgen]
impl Keys {
    /// Hybrid X25519 + ML-KEM-768 public (encapsulation) key bytes.
    #[wasm_bindgen(getter, js_name = "kemPublicKey")]
    pub fn kem_public_key(&self) -> Vec<u8> {
        self.kem_public_key.clone()
    }

    /// Hybrid X25519 + ML-KEM-768 secret (decapsulation) key bytes.
    #[wasm_bindgen(getter, js_name = "kemSecretKey")]
    pub fn kem_secret_key(&self) -> Vec<u8> {
        self.kem_secret_key.clone()
    }

    /// Hybrid Ed25519 + ML-DSA-65 public (verifying) key bytes.
    #[wasm_bindgen(getter, js_name = "signPublicKey")]
    pub fn sign_public_key(&self) -> Vec<u8> {
        self.sign_public_key.clone()
    }

    /// Hybrid Ed25519 + ML-DSA-65 secret (signing) key bytes.
    #[wasm_bindgen(getter, js_name = "signSecretKey")]
    pub fn sign_secret_key(&self) -> Vec<u8> {
        self.sign_secret_key.clone()
    }
}

// ── Internal functions (testable on native targets) ──────────────────────────

/// Generate keys and return the raw `Keys` struct.
///
/// Returns `Result<Keys, String>` so both wasm-bindgen exports and native
/// tests can use it without depending on `JsError` (which panics off-wasm).
///
/// The KEM secret key is serialized as a self-contained blob that includes
/// the ML-KEM public key bytes needed for decapsulation (KitchenSink combiner).
/// Format: `[4-byte LE sk_len] || [sk_bytes] || [pk_bytes]`
pub(crate) fn generate_keys_internal() -> Result<Keys, String> {
    let kp = lupine::easy::generate_keys().map_err(|e| e.to_string())?;

    // Bundle KEM SK + PK into a single self-contained blob so that
    // decrypt_internal can reconstruct a working HybridKemSecretKey768
    // (which needs mlkem_pk_bytes for the KitchenSink combiner).
    let sk_bytes = kp.kem_sk.to_bytes();
    let pk_bytes = kp.kem_pk.to_bytes();
    let sk_len = sk_bytes.len() as u32;
    let mut kem_secret_key = Vec::with_capacity(4 + sk_bytes.len() + pk_bytes.len());
    kem_secret_key.extend_from_slice(&sk_len.to_le_bytes());
    kem_secret_key.extend_from_slice(&sk_bytes);
    kem_secret_key.extend_from_slice(&pk_bytes);

    Ok(Keys {
        kem_public_key: pk_bytes,
        kem_secret_key,
        sign_public_key: kp.sign_pk.to_bytes(),
        sign_secret_key: kp.sign_sk.to_bytes(),
    })
}

/// Encrypt plaintext for a recipient's KEM public key (internal).
pub(crate) fn encrypt_internal(kem_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let pk = HybridKemPublicKey768::from_bytes(kem_public_key).map_err(|e| e.to_string())?;
    lupine::easy::encrypt(&pk, plaintext).map_err(|e| e.to_string())
}

/// Decrypt sealed data with the recipient's KEM secret key (internal).
///
/// Expects `kem_secret_key` in the bundled format produced by
/// [`generate_keys_internal`]: `[4-byte LE sk_len] || [sk_bytes] || [pk_bytes]`.
/// The ML-KEM public key bytes are restored so the KitchenSink combiner works.
pub(crate) fn decrypt_internal(kem_secret_key: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    if kem_secret_key.len() < 4 {
        return Err("KEM secret key too short (missing length prefix)".to_string());
    }
    let sk_len = u32::from_le_bytes(kem_secret_key[..4].try_into().unwrap()) as usize;
    if kem_secret_key.len() < 4 + sk_len {
        return Err("KEM secret key too short (truncated SK bytes)".to_string());
    }
    let sk_bytes = &kem_secret_key[4..4 + sk_len];
    let pk_bytes = &kem_secret_key[4 + sk_len..];

    let mut sk = HybridKemSecretKey768::from_bytes(sk_bytes).map_err(|e| e.to_string())?;
    // Restore the ML-KEM public key bytes (X25519 pk is first 32 bytes of pk_bytes,
    // ML-KEM pk is the remainder). from_bytes leaves mlkem_pk_bytes empty.
    if pk_bytes.len() > 32 {
        sk.set_mlkem_pk_bytes(pk_bytes[32..].to_vec());
    }
    lupine::easy::decrypt(&sk, sealed).map_err(|e| e.to_string())
}

/// Sign message with a signing key (internal).
pub(crate) fn sign_internal(signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let sk = HybridSigningKey65::from_bytes(signing_key).map_err(|e| e.to_string())?;
    lupine::easy::sign(&sk, message).map_err(|e| e.to_string())
}

/// Verify a signature against a public key and message (internal).
pub(crate) fn verify_internal(
    verifying_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, String> {
    let pk = HybridVerifyingKey65::from_bytes(verifying_key).map_err(|e| e.to_string())?;
    lupine::easy::verify(&pk, message, signature).map_err(|e| e.to_string())
}

// ── WASM API ─────────────────────────────────────────────────────────────────

/// Generate a new PQC keypair (hybrid X25519+ML-KEM-768 for encryption,
/// hybrid Ed25519+ML-DSA-65 for signing).
///
/// Returns a [`Keys`] object with four `Uint8Array` getters.
#[wasm_bindgen(js_name = "generateKeys")]
pub fn generate_keys() -> Result<Keys, JsError> {
    generate_keys_internal().map_err(|e| JsError::new(&e))
}

/// Encrypt `plaintext` for a recipient's KEM public key.
///
/// Uses KEM-DEM hybrid encryption: X25519+ML-KEM-768 key encapsulation
/// followed by ChaCha20-Poly1305 AEAD.
///
/// Returns the sealed ciphertext as a `Uint8Array`.
#[wasm_bindgen]
pub fn encrypt(kem_public_key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
    encrypt_internal(kem_public_key, plaintext).map_err(|e| JsError::new(&e))
}

/// Decrypt sealed data with the recipient's KEM secret key.
///
/// Reverses the KEM-DEM construction: decapsulates the shared secret and
/// authenticates + decrypts the ChaCha20-Poly1305 payload.
///
/// Returns the plaintext as a `Uint8Array`.
#[wasm_bindgen]
pub fn decrypt(kem_secret_key: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsError> {
    decrypt_internal(kem_secret_key, sealed).map_err(|e| JsError::new(&e))
}

/// Sign `message` with a hybrid Ed25519+ML-DSA-65 signing key.
///
/// Returns the composite signature bytes as a `Uint8Array`.
#[wasm_bindgen]
pub fn sign(signing_key: &[u8], message: &[u8]) -> Result<Vec<u8>, JsError> {
    sign_internal(signing_key, message).map_err(|e| JsError::new(&e))
}

/// Verify a signature against a public key and message.
///
/// Returns `true` if the signature is valid, `false` if it is cryptographically
/// invalid. Throws on structurally malformed inputs (wrong key size, truncated
/// signature bytes).
#[wasm_bindgen]
pub fn verify(verifying_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsError> {
    verify_internal(verifying_key, message, signature).map_err(|e| JsError::new(&e))
}

// ── Native tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `f` on a thread with a 32 MB stack.
    ///
    /// ML-DSA-65 operations allocate large on-stack intermediates in debug
    /// builds that exceed the default 8 MB thread stack. All tests use this
    /// wrapper to avoid stack overflow.
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn native_keygen_succeeds() {
        with_large_stack(|| {
            let keys = generate_keys_internal().expect("keygen must succeed");
            assert!(
                !keys.kem_public_key.is_empty(),
                "KEM public key must not be empty"
            );
            assert!(
                !keys.kem_secret_key.is_empty(),
                "KEM secret key must not be empty"
            );
            assert!(
                !keys.sign_public_key.is_empty(),
                "sign public key must not be empty"
            );
            assert!(
                !keys.sign_secret_key.is_empty(),
                "sign secret key must not be empty"
            );
        });
    }

    #[test]
    fn native_keygen_encrypt_decrypt() {
        with_large_stack(|| {
            let keys = generate_keys_internal().expect("keygen");
            let plaintext = b"hello post-quantum wasm world";
            let sealed = encrypt_internal(&keys.kem_public_key, plaintext).expect("encrypt");
            let recovered = decrypt_internal(&keys.kem_secret_key, &sealed).expect("decrypt");
            assert_eq!(recovered.as_slice(), plaintext.as_slice());
        });
    }

    #[test]
    fn native_encrypt_decrypt_empty() {
        with_large_stack(|| {
            let keys = generate_keys_internal().expect("keygen");
            let sealed = encrypt_internal(&keys.kem_public_key, b"").expect("encrypt empty");
            let recovered = decrypt_internal(&keys.kem_secret_key, &sealed).expect("decrypt empty");
            assert!(recovered.is_empty());
        });
    }

    #[test]
    fn native_sign_verify() {
        with_large_stack(|| {
            let keys = generate_keys_internal().expect("keygen");
            let message = b"sign me in wasm";
            let sig = sign_internal(&keys.sign_secret_key, message).expect("sign");
            let valid = verify_internal(&keys.sign_public_key, message, &sig).expect("verify");
            assert!(valid, "valid signature must verify");
        });
    }

    #[test]
    fn native_verify_wrong_key_returns_false() {
        with_large_stack(|| {
            let alice = generate_keys_internal().expect("keygen alice");
            let bob = generate_keys_internal().expect("keygen bob");
            let message = b"signed by alice";
            let sig = sign_internal(&alice.sign_secret_key, message).expect("sign");
            let valid = verify_internal(&bob.sign_public_key, message, &sig).expect("verify");
            assert!(!valid, "alice's signature must not verify with bob's key");
        });
    }

    #[test]
    fn native_decrypt_wrong_key_fails() {
        with_large_stack(|| {
            let alice = generate_keys_internal().expect("keygen alice");
            let bob = generate_keys_internal().expect("keygen bob");
            let sealed = encrypt_internal(&alice.kem_public_key, b"for alice").expect("encrypt");
            let result = decrypt_internal(&bob.kem_secret_key, &sealed);
            assert!(result.is_err(), "decrypting with wrong key must fail");
        });
    }

    #[test]
    fn native_encrypt_invalid_key_fails() {
        let result = encrypt_internal(&[0u8; 4], b"test");
        assert!(result.is_err(), "encrypt with invalid key must fail");
    }

    #[test]
    fn native_decrypt_invalid_key_fails() {
        let result = decrypt_internal(&[0u8; 4], &[0u8; 1200]);
        assert!(result.is_err(), "decrypt with invalid key must fail");
    }

    #[test]
    fn native_sign_invalid_key_fails() {
        let result = sign_internal(&[0u8; 4], b"test");
        assert!(result.is_err(), "sign with invalid key must fail");
    }

    #[test]
    fn native_verify_invalid_key_fails() {
        let result = verify_internal(&[0u8; 4], b"test", &[0u8; 100]);
        assert!(result.is_err(), "verify with invalid key must fail");
    }
}
