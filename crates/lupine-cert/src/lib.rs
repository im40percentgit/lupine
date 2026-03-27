//! X.509v3 certificate generation and validation for the Lupine PQC suite.
//!
//! This crate provides:
//!
//! - [`asn1`] — X.509 ASN.1 structures (TbsCertificate, X509Certificate, etc.)
//! - [`generate`] — Self-signed and CA-signed certificate generation
//! - [`parse`] — Certificate parsing from DER/PEM
//! - [`validate`] — Certificate chain validation
//!
//! # Quick example
//!
//! ```rust,ignore
//! use lupine_cert::generate::CertBuilder;
//! use lupine_core::SignAlgorithm;
//!
//! let cert = CertBuilder::new()
//!     .subject("CN=example")
//!     .self_signed(SignAlgorithm::MlDsa65)
//!     .unwrap();
//! ```

pub mod asn1;
pub mod generate;
pub mod parse;
pub mod validate;
