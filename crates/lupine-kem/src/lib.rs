//! KEM implementations for the Lupine PQC suite.
//!
//! Provides ML-KEM (FIPS 203) wrappers for all three parameter sets
//! (ML-KEM-512, ML-KEM-768, ML-KEM-1024) and, in future phases, hybrid
//! X25519+ML-KEM constructions.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod mlkem;

pub use mlkem::{
    generate_keypair,
    MlKemPublicKey, MlKemSecretKey, MlKemCiphertext, MlKemSharedKey,
    MlKemPublicKey512, MlKemSecretKey512, MlKemCiphertext512,
    MlKemPublicKey768, MlKemSecretKey768, MlKemCiphertext768,
    MlKemPublicKey1024, MlKemSecretKey1024, MlKemCiphertext1024,
};
