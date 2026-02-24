//! Core types, traits, and error handling for the Lupine PQC suite.
//!
//! This crate is `no_std` compatible when the `std` feature is disabled.
//! Enable `std` (the default) to get `std::error::Error` implementations.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod error;
pub mod params;
pub mod traits;

#[cfg(feature = "alloc")]
pub mod types;

pub use error::{Error, Result, SerializationError};
pub use params::{KemAlgorithm, SignAlgorithm};
pub use traits::SecurityLevel;

#[cfg(feature = "alloc")]
pub use types::SharedSecret;
