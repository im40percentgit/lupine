//! Lupine — Post-Quantum Cryptographic Suite (FIPS 203/204/205).
//!
//! This crate is the top-level facade re-exporting everything from the
//! constituent Lupine crates. Import `lupine` to get access to all
//! KEM, signature, and serialization types without managing multiple crate
//! dependencies directly.
//!
//! # Quick start (easy API)
//!
//! The [`easy`] module provides a defaults-first interface for the most common
//! operations. It selects secure algorithms automatically — you do not need to
//! choose parameter sets.
//!
//! ```rust
//! use lupine::easy;
//!
//! // Generate a keypair (hybrid X25519+ML-KEM-768 for KEM,
//! //                      hybrid Ed25519+ML-DSA-65 for signing).
//! let alice = easy::generate_keys().unwrap();
//! let bob   = easy::generate_keys().unwrap();
//!
//! // Bob encrypts a message for Alice.
//! let sealed = easy::encrypt(&alice.kem_pk, b"hello post-quantum world").unwrap();
//!
//! // Alice decrypts it.
//! let plain = easy::decrypt(&alice.kem_sk, &sealed).unwrap();
//! assert_eq!(plain, b"hello post-quantum world");
//!
//! // Alice signs a release note.
//! let sig = easy::sign(&alice.sign_sk, b"release v1.0").unwrap();
//!
//! // Bob verifies it.
//! assert!(easy::verify(&alice.sign_pk, b"release v1.0", &sig).unwrap());
//! ```
//!
//! # Crate map
//!
//! | Re-export | Source crate | Contents |
//! |-----------|-------------|---------|
//! | `lupine::kem` | `lupine-kem` | ML-KEM (FIPS 203), hybrid X25519+ML-KEM |
//! | `lupine::sign` | `lupine-sign` | ML-DSA (FIPS 204), SLH-DSA (FIPS 205), hybrid Ed25519+ML-DSA |
//! | `lupine::serial` | `lupine-serial` | DER/PEM/SPKI/composite serialization |
//! | `lupine::core` | `lupine-core` | Error types, algorithm enums, `SecurityLevel` |
//! | `lupine::easy` | (this crate) | High-level encrypt/decrypt/sign/verify (feature `easy`) |
//!
//! # Feature flags
//!
//! | Feature | Default | Effect |
//! |---------|---------|--------|
//! | `std`   | yes     | Enables `std::error::Error` impls and allocator |
//! | `easy`  | yes     | Compiles [`easy`] module (AEAD, HKDF, OsRng) |
//! | `alloc` | no      | `no_std` with allocator (keys and ciphertexts only) |
//!
//! Disable `default-features` and enable only `alloc` for embedded targets
//! that do not have the `easy` API's AEAD/HKDF dependencies available.

#![cfg_attr(not(feature = "std"), no_std)]

pub use lupine_core as core;
pub use lupine_kem as kem;
pub use lupine_serial as serial;
pub use lupine_sign as sign;

#[cfg(feature = "easy")]
pub mod easy;
