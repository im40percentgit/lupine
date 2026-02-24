//! KEM implementations for the Lupine PQC suite.
//!
//! Provides ML-KEM (FIPS 203) wrappers for all three parameter sets
//! (ML-KEM-512, ML-KEM-768, ML-KEM-1024) and hybrid X25519+ML-KEM
//! constructions (Phase 3).
//!
//! # Crate structure
//!
//! - [`mlkem`] — ML-KEM wrappers (FIPS 203)
//! - [`hybrid`] — Hybrid X25519+ML-KEM KEM with KitchenSink combiner
//! - [`combiner`] — HKDF-SHA-256 KitchenSink KDF used by the hybrid KEM

#![cfg_attr(not(feature = "std"), no_std)]

pub mod combiner;
pub mod hybrid;
pub mod mlkem;

pub use mlkem::{
    generate_keypair,
    MlKemPublicKey, MlKemSecretKey, MlKemCiphertext, MlKemSharedKey,
    MlKemPublicKey512, MlKemSecretKey512, MlKemCiphertext512,
    MlKemPublicKey768, MlKemSecretKey768, MlKemCiphertext768,
    MlKemPublicKey1024, MlKemSecretKey1024, MlKemCiphertext1024,
};

pub use hybrid::{
    generate_keypair as hybrid_generate_keypair,
    HybridKemPublicKey, HybridKemSecretKey, HybridKemCiphertext,
    HybridKemPublicKey512, HybridKemSecretKey512, HybridKemCiphertext512,
    HybridKemPublicKey768, HybridKemSecretKey768, HybridKemCiphertext768,
    HybridKemPublicKey1024, HybridKemSecretKey1024, HybridKemCiphertext1024,
};
