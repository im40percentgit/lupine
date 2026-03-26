//! Encrypt and decrypt a file using the `lupine::easy` high-level API.
//!
//! Demonstrates:
//! - Key generation (hybrid X25519+ML-KEM-768)
//! - File encryption to a `.enc` file
//! - File decryption back to plaintext
//! - Verification that the round-trip produces the original bytes
//!
//! # Usage
//!
//! ```text
//! cargo run --example encrypt_file --features easy
//! ```
//!
//! The example writes temporary files to the current directory and removes them
//! at the end.
//!
//! @decision DEC-EXAMPLE-001
//! @title Example programs use lupine::easy, not raw primitives
//! @status accepted
//! @rationale The examples/ directory targets new users who want to see "how do
//!   I encrypt a file?" without reading FIPS 203/204 first. The easy API hides
//!   algorithm selection (hybrid X25519+ML-KEM-768 for KEM, ChaCha20-Poly1305
//!   for AEAD) and lets the example focus on the user-visible workflow. Raw
//!   primitive usage is demonstrated separately in kem_raw.rs for users who
//!   need the lower-level API.

use std::fs;

use lupine::easy;

fn main() {
    // Run on a large-stack thread — ML-DSA key generation allocates ~16 MB on
    // the stack in debug builds, which exceeds the default OS thread stack.
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .name("encrypt-file-example".into())
        .spawn(run)
        .expect("failed to spawn thread")
        .join()
        .expect("thread panicked");
}

fn run() {
    // ── 1. Key generation ──────────────────────────────────────────────────
    println!("Generating keypair...");
    let recipient = easy::generate_keys().expect("key generation failed");
    println!(
        "  KEM public key:  {} bytes",
        recipient.kem_pk.to_bytes().len()
    );

    // ── 2. Prepare a plaintext file ────────────────────────────────────────
    let plaintext_path = "example_plaintext.txt";
    let encrypted_path = "example_plaintext.txt.enc";
    let plaintext = b"Hello, post-quantum world!\n\
        This file is encrypted with Hybrid X25519+ML-KEM-768\n\
        and authenticated with ChaCha20-Poly1305.\n";

    fs::write(plaintext_path, plaintext).expect("failed to write plaintext file");
    println!(
        "Wrote plaintext ({} bytes) to {plaintext_path}",
        plaintext.len()
    );

    // ── 3. Encrypt ─────────────────────────────────────────────────────────
    let contents = fs::read(plaintext_path).expect("failed to read plaintext");
    let sealed = easy::encrypt(&recipient.kem_pk, &contents).expect("encryption failed");
    fs::write(encrypted_path, &sealed).expect("failed to write encrypted file");
    println!(
        "Encrypted to {encrypted_path} ({} bytes, overhead = {} bytes)",
        sealed.len(),
        sealed.len() - contents.len()
    );

    // ── 4. Decrypt ─────────────────────────────────────────────────────────
    let sealed_bytes = fs::read(encrypted_path).expect("failed to read encrypted file");
    let recovered = easy::decrypt(&recipient.kem_sk, &sealed_bytes).expect("decryption failed");
    println!("Decrypted {} bytes", recovered.len());

    // ── 5. Verify round-trip ───────────────────────────────────────────────
    assert_eq!(
        recovered.as_slice(),
        plaintext.as_slice(),
        "decrypted bytes do not match original plaintext"
    );
    println!("Round-trip verified: decrypted bytes match original.");

    // ── 6. Demonstrate authentication (tamper detection) ───────────────────
    let mut tampered = sealed_bytes.clone();
    // Flip a byte deep in the AEAD ciphertext region (past the KEM ciphertext
    // and nonce) to simulate an integrity attack.
    let flip_pos = sealed_bytes.len() - 20;
    tampered[flip_pos] ^= 0xFF;
    match easy::decrypt(&recipient.kem_sk, &tampered) {
        Err(easy::Error::Aead) => {
            println!("Tamper detection: AEAD correctly rejected the modified ciphertext.");
        }
        other => panic!("expected Aead error for tampered ciphertext, got: {other:?}"),
    }

    // ── 7. Cleanup ─────────────────────────────────────────────────────────
    let _ = fs::remove_file(plaintext_path);
    let _ = fs::remove_file(encrypted_path);
    println!("Done.");
}
