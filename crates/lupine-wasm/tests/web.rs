//! WASM browser tests for lupine-wasm.
//!
//! These tests require `wasm-pack test --headless --chrome` or similar.
//! They validate the full wasm-bindgen surface in a browser-like environment.

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

#[wasm_bindgen_test]
fn keygen_encrypt_decrypt_roundtrip() {
    let keys = lupine_wasm::generate_keys().unwrap();
    let plaintext = b"hello post-quantum world";
    let sealed = lupine_wasm::encrypt(&keys.kem_public_key(), plaintext).unwrap();
    let decrypted = lupine_wasm::decrypt(&keys.kem_secret_key(), &sealed).unwrap();
    assert_eq!(decrypted, plaintext);
}

#[wasm_bindgen_test]
fn sign_verify_roundtrip() {
    let keys = lupine_wasm::generate_keys().unwrap();
    let message = b"sign me";
    let sig = lupine_wasm::sign(&keys.sign_secret_key(), message).unwrap();
    let valid = lupine_wasm::verify(&keys.sign_public_key(), message, &sig).unwrap();
    assert!(valid);
}

#[wasm_bindgen_test]
fn verify_wrong_message_returns_false() {
    let keys = lupine_wasm::generate_keys().unwrap();
    let sig = lupine_wasm::sign(&keys.sign_secret_key(), b"original").unwrap();
    let valid = lupine_wasm::verify(&keys.sign_public_key(), b"tampered", &sig).unwrap();
    assert!(!valid);
}
