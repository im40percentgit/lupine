//! Signature implementations for the Lupine PQC suite.
//!
//! Provides ML-DSA (FIPS 204), SLH-DSA (FIPS 205), and hybrid Ed25519+ML-DSA
//! wrappers with a Lupine-idiomatic API: byte-oriented key serialization,
//! Lupine `Error`/`Result` types, and consistent patterns matching `lupine-kem`.
//!
//! # Crate structure
//!
//! - [`mldsa`] — ML-DSA (Dilithium) wrappers for parameter sets 44, 65, 87
//! - [`slhdsa`] — SLH-DSA (SPHINCS+) wrappers for all 12 FIPS 205 parameter sets
//! - [`hybrid`] — Hybrid Ed25519+ML-DSA with AND-verify (Phase 3)

#![cfg_attr(not(feature = "std"), no_std)]

pub mod hybrid;
pub mod mldsa;
pub mod slhdsa;

pub use mldsa::{
    MlDsa44Signature, MlDsa44SigningKey, MlDsa44VerifyingKey,
    MlDsa65Signature, MlDsa65SigningKey, MlDsa65VerifyingKey,
    MlDsa87Signature, MlDsa87SigningKey, MlDsa87VerifyingKey,
    MlDsaSignature, MlDsaSigningKey, MlDsaVerifyingKey,
    generate_keypair as ml_dsa_generate_keypair,
};

pub use hybrid::{
    generate_keypair as hybrid_generate_keypair,
    HybridSigningKey, HybridVerifyingKey, HybridSignature,
    HybridSigningKey44, HybridVerifyingKey44, HybridSignature44,
    HybridSigningKey65, HybridVerifyingKey65, HybridSignature65,
    HybridSigningKey87, HybridVerifyingKey87, HybridSignature87,
};

pub use slhdsa::{
    SlhDsaSignature, SlhDsaSigningKey, SlhDsaVerifyingKey,
    // SHA2 variants
    SlhDsaSha2_128sSigningKey, SlhDsaSha2_128sVerifyingKey, SlhDsaSha2_128sSignature,
    SlhDsaSha2_128fSigningKey, SlhDsaSha2_128fVerifyingKey, SlhDsaSha2_128fSignature,
    SlhDsaSha2_192sSigningKey, SlhDsaSha2_192sVerifyingKey, SlhDsaSha2_192sSignature,
    SlhDsaSha2_192fSigningKey, SlhDsaSha2_192fVerifyingKey, SlhDsaSha2_192fSignature,
    SlhDsaSha2_256sSigningKey, SlhDsaSha2_256sVerifyingKey, SlhDsaSha2_256sSignature,
    SlhDsaSha2_256fSigningKey, SlhDsaSha2_256fVerifyingKey, SlhDsaSha2_256fSignature,
    // SHAKE variants
    SlhDsaShake128sSigningKey, SlhDsaShake128sVerifyingKey, SlhDsaShake128sSignature,
    SlhDsaShake128fSigningKey, SlhDsaShake128fVerifyingKey, SlhDsaShake128fSignature,
    SlhDsaShake192sSigningKey, SlhDsaShake192sVerifyingKey, SlhDsaShake192sSignature,
    SlhDsaShake192fSigningKey, SlhDsaShake192fVerifyingKey, SlhDsaShake192fSignature,
    SlhDsaShake256sSigningKey, SlhDsaShake256sVerifyingKey, SlhDsaShake256sSignature,
    SlhDsaShake256fSigningKey, SlhDsaShake256fVerifyingKey, SlhDsaShake256fSignature,
    generate_keypair as slh_dsa_generate_keypair,
};
