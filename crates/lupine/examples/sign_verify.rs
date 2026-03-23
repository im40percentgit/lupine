//! Sign and verify data using the `lupine::easy` high-level API.
//!
//! Demonstrates:
//! - Key generation (hybrid Ed25519+ML-DSA-65)
//! - Signing arbitrary bytes
//! - Successful verification with the correct key
//! - Failed verification with a wrong key (returns `Ok(false)`, not an error)
//! - Failed verification over tampered data
//!
//! # Usage
//!
//! ```text
//! cargo run --example sign_verify --features easy
//! ```
//!
//! @decision DEC-EXAMPLE-002
//! @title Hybrid Ed25519+ML-DSA-65 as the default signing algorithm
//! @status accepted
//! @rationale The easy API defaults to the hybrid Ed25519+ML-DSA-65 scheme
//!   (NIST Security Level 3) because it provides defense-in-depth: security
//!   holds as long as either Ed25519 (classical) or ML-DSA-65 (post-quantum)
//!   remains unbroken. The Level 3 parameter set balances key/signature size
//!   against security margin. Users who need smaller signatures (ML-DSA-44)
//!   or higher security (ML-DSA-87) can use lupine::sign directly.

use lupine::easy;

fn main() {
    // ML-DSA operations allocate large on-stack intermediates in debug builds.
    // Dispatch all work to a 32 MiB thread to avoid stack overflows.
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .name("sign-verify-example".into())
        .spawn(run)
        .expect("failed to spawn thread")
        .join()
        .expect("thread panicked");
}

fn run() {
    // ── 1. Key generation ──────────────────────────────────────────────────
    println!("Generating keypairs for Alice and Bob...");
    let alice = easy::generate_keys().expect("alice keygen failed");
    let bob   = easy::generate_keys().expect("bob keygen failed");
    println!(
        "  Alice signing key:   {} bytes (secret)",
        alice.sign_sk.to_bytes().len()
    );
    println!(
        "  Alice verifying key: {} bytes (public)",
        alice.sign_pk.to_bytes().len()
    );

    // ── 2. Alice signs a release announcement ─────────────────────────────
    let data = b"Lupine v1.0: post-quantum cryptography suite, FIPS 203/204/205 compliant.";
    let signature = easy::sign(&alice.sign_sk, data).expect("signing failed");
    println!("\nAlice signed {} bytes of data.", data.len());
    println!("Signature size: {} bytes (Ed25519 + ML-DSA-65 composite).", signature.len());

    // ── 3. Bob verifies with Alice's public key ────────────────────────────
    let valid = easy::verify(&alice.sign_pk, data, &signature)
        .expect("verify returned an unexpected error");
    assert!(valid, "Alice's signature must verify with her own key");
    println!("\nBob verified: signature is valid.");

    // ── 4. Wrong key: Bob's key cannot verify Alice's signature ───────────
    // verify() returns Ok(false) for cryptographic failures, not Err(…).
    // An Err return would indicate the signature bytes are structurally invalid.
    let wrong_key = easy::verify(&bob.sign_pk, data, &signature)
        .expect("verify must not return Err for a structurally valid signature");
    assert!(!wrong_key, "Alice's signature must not verify with Bob's key");
    println!("Wrong key check: Bob's key correctly rejected Alice's signature.");

    // ── 5. Tampered data: signature no longer matches ─────────────────────
    let tampered_data = b"Lupine v1.0: TAMPERED ANNOUNCEMENT";
    let tampered_valid = easy::verify(&alice.sign_pk, tampered_data, &signature)
        .expect("verify must not return Err for a valid signature over different data");
    assert!(!tampered_valid, "signature must not verify over tampered data");
    println!("Tamper check: signature correctly rejected for modified data.");

    // ── 6. Verify that an empty message can also be signed ─────────────────
    let empty_sig = easy::sign(&alice.sign_sk, b"").expect("sign empty");
    let empty_ok  = easy::verify(&alice.sign_pk, b"", &empty_sig)
        .expect("verify empty");
    assert!(empty_ok, "empty-message signature must verify");
    println!("Empty message: sign/verify round-trip succeeded.");

    println!("\nDone.");
}
