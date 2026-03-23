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
    generate_keypair, MlKemCiphertext, MlKemCiphertext1024, MlKemCiphertext512, MlKemCiphertext768,
    MlKemPublicKey, MlKemPublicKey1024, MlKemPublicKey512, MlKemPublicKey768, MlKemSecretKey,
    MlKemSecretKey1024, MlKemSecretKey512, MlKemSecretKey768, MlKemSharedKey,
};

pub use hybrid::{
    generate_keypair as hybrid_generate_keypair, HybridKemCiphertext, HybridKemCiphertext1024,
    HybridKemCiphertext512, HybridKemCiphertext768, HybridKemPublicKey, HybridKemPublicKey1024,
    HybridKemPublicKey512, HybridKemPublicKey768, HybridKemSecretKey, HybridKemSecretKey1024,
    HybridKemSecretKey512, HybridKemSecretKey768,
};
