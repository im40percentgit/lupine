//! ML-KEM key exchange using the `lupine::kem` lower-level API directly.
//!
//! Demonstrates:
//! - Direct use of `lupine_kem::mlkem` (ML-KEM-768, FIPS 203)
//! - Key generation, encapsulation, decapsulation
//! - Key serialization and deserialization (the `from_bytes`/`to_bytes` API)
//! - Verification that both sides derive the same shared secret
//! - Comparison with the hybrid X25519+ML-KEM variant
//!
//! This example shows the lower-level API. For most applications, prefer
//! `lupine::easy::encrypt`/`decrypt` which handles KDF and AEAD on top of the
//! shared secret automatically.
//!
//! # Usage
//!
//! ```text
//! cargo run --example kem_raw
//! ```
//!
//! @decision DEC-EXAMPLE-003
//! @title kem_raw uses ML-KEM-768 (not 512 or 1024) as the illustrative set
//! @status accepted
//! @rationale ML-KEM-768 is the NIST-recommended default (Security Level 3,
//!   AES-192 equivalent). Using it in the raw example aligns with the easy
//!   API default and gives readers a representative view of real-world key and
//!   ciphertext sizes. The generic `generate_keypair::<P>` API is shown
//!   explicitly so readers can see how to substitute ML-KEM-512 or ML-KEM-1024.

use lupine::kem::mlkem::{generate_keypair, MlKemPublicKey768, MlKemSecretKey768};
use rand::rngs::OsRng;

fn main() {
    // ── 1. Key generation ──────────────────────────────────────────────────
    // generate_keypair is generic over the ML-KEM parameter set. The type
    // parameter determines the security level and key/ciphertext sizes.
    // Substitute ml_kem::MlKem512 or ml_kem::MlKem1024 for other levels.
    println!("ML-KEM-768 key exchange (FIPS 203, NIST Security Level 3)\n");

    let mut rng = OsRng;
    let (secret_key, public_key) = generate_keypair::<ml_kem::MlKem768>(&mut rng)
        .expect("key generation failed");

    println!("Key sizes:");
    println!("  Public (encapsulation) key: {} bytes", public_key.to_bytes().len());
    println!("  Secret (decapsulation) key: {} bytes", secret_key.to_bytes().len());

    // ── 2. Key serialization round-trip ────────────────────────────────────
    // In practice a sender receives the recipient's public key over the wire.
    // Serialize and deserialize to simulate that transfer.
    let pk_bytes = public_key.to_bytes().to_vec();
    let sk_bytes = secret_key.to_bytes().to_vec();

    let received_pk = MlKemPublicKey768::from_bytes(&pk_bytes)
        .expect("public key deserialization failed");
    let loaded_sk = MlKemSecretKey768::from_bytes(&sk_bytes)
        .expect("secret key deserialization failed");

    println!("\nKey serialization round-trip: OK");

    // ── 3. Encapsulation (sender side) ─────────────────────────────────────
    // The sender calls encapsulate() on the recipient's public key.
    // This produces:
    //   - a ciphertext to send to the recipient
    //   - a shared secret that the sender keeps (never transmitted)
    let (ciphertext, sender_secret) = received_pk.encapsulate(&mut rng)
        .expect("encapsulation failed");

    println!("\nEncapsulation:");
    println!("  Ciphertext:    {} bytes (sent to recipient)", ciphertext.to_bytes().len());
    println!("  Shared secret: {} bytes (sender keeps this)", sender_secret.as_bytes().len());

    // ── 4. Decapsulation (recipient side) ──────────────────────────────────
    // The recipient calls decapsulate() on their secret key and the ciphertext.
    // Per FIPS 203 §6.4, decapsulation always succeeds: if the ciphertext is
    // invalid, a pseudorandom "implicit rejection" secret is returned instead
    // of an error. This prevents timing-based ciphertext validity oracles.
    let recipient_secret = loaded_sk.decapsulate(&ciphertext)
        .expect("decapsulation failed");

    println!("\nDecapsulation:");
    println!("  Shared secret: {} bytes (recipient derives this)", recipient_secret.as_bytes().len());

    // ── 5. Verify both sides have the same secret ──────────────────────────
    assert_eq!(
        sender_secret.as_bytes(),
        recipient_secret.as_bytes(),
        "sender and recipient shared secrets must match"
    );
    println!("\nShared secret matches on both sides.");
    println!(
        "  First 8 bytes (hex): {}",
        sender_secret.as_bytes()[..8]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join("")
    );

    // ── 6. Hybrid variant (for comparison) ────────────────────────────────
    // The hybrid X25519+ML-KEM-768 variant adds a classical DH component so
    // security holds if either X25519 or ML-KEM is broken.
    println!("\n── Hybrid X25519+ML-KEM-768 (for comparison) ──");
    use lupine::kem::hybrid_generate_keypair;
    let (hybrid_sk, hybrid_pk) = hybrid_generate_keypair::<ml_kem::MlKem768>(&mut rng)
        .expect("hybrid keygen failed");
    let (hybrid_ct, hybrid_ss_send) = hybrid_pk.encapsulate(&mut rng)
        .expect("hybrid encapsulate failed");
    let hybrid_ss_recv = hybrid_sk.decapsulate(&hybrid_ct)
        .expect("hybrid decapsulate failed");
    assert_eq!(hybrid_ss_send.as_bytes(), hybrid_ss_recv.as_bytes());

    println!("  Hybrid public key:  {} bytes (X25519 || ML-KEM-768)", hybrid_pk.to_bytes().len());
    println!("  Hybrid ciphertext:  {} bytes (ephemeral X25519 pk || ML-KEM ct)", hybrid_ct.to_bytes().len());
    println!("  Hybrid shared secret: {} bytes — matches on both sides.", hybrid_ss_send.as_bytes().len());

    println!("\nDone.");
}
