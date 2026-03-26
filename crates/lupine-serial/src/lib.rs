//! Serialization (DER, PEM, SPKI, composite) for the Lupine PQC suite.
//!
//! This crate provides encoding and decoding for all Lupine key types:
//!
//! - [`der`] — DER (`SEQUENCE { AlgorithmIdentifier, OCTET STRING }`) for
//!   public keys, secret keys, and detached signatures.
//! - [`pem`] — RFC 7468 PEM wrapping around DER bytes.
//! - [`spki`] — SubjectPublicKeyInfo (RFC 5280 §4.1.2.7) for public keys,
//!   using `BIT STRING` as required by X.509.
//! - [`composite`] — Composite key/signature format for hybrid types
//!   (X25519+ML-KEM, Ed25519+ML-DSA).
//! - [`oid`] — NIST-assigned OID constants for all supported algorithms.
//!
//! # Quick example
//!
//! ```rust,ignore
//! use lupine_serial::{der, pem};
//! use lupine_core::KemAlgorithm;
//!
//! // Encode a KEM public key as PEM
//! let raw_key: &[u8] = &[0u8; 800]; // placeholder
//! let der_bytes = der::encode_kem_public_key_der(KemAlgorithm::MlKem768, raw_key).unwrap();
//! let pem_str = pem::encode_public_key_pem(&der_bytes).unwrap();
//!
//! // Round-trip back
//! let der2 = pem::decode_public_key_pem(&pem_str).unwrap();
//! let (alg, key) = der::decode_kem_public_key_der(&der2).unwrap();
//! assert_eq!(alg, KemAlgorithm::MlKem768);
//! ```

#![cfg_attr(not(feature = "std"), no_std)]

pub mod composite;
pub mod der;
pub mod oid;
pub mod pem;
pub mod spki;
pub mod ssh;
