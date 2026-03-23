//! Lupine — Post-Quantum Cryptographic Suite (FIPS 203/204/205).
//!
//! This crate is the top-level facade re-exporting everything from the
//! constituent Lupine crates. Import `lupine` to get access to all
//! KEM, signature, and serialization types without managing multiple crate
//! dependencies directly.

#![cfg_attr(not(feature = "std"), no_std)]

pub use lupine_core as core;
pub use lupine_kem as kem;
pub use lupine_serial as serial;
pub use lupine_sign as sign;

#[cfg(feature = "easy")]
pub mod easy;
