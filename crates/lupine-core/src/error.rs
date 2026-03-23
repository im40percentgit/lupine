//! Unified error type for the Lupine PQC suite.
//!
//! All operations across lupine crates surface errors through this single
//! `Error` enum, making it straightforward to use `?` across crate boundaries.
//!
//! @decision DEC-CORE-001
//! @title Single error enum vs per-crate error types
//! @status accepted
//! @rationale A single unified Error enum keeps the public API simple: callers
//!   import one type, match on meaningful variants, and never deal with nested
//!   conversion chains. The cost (enum grows as crates grow) is acceptable for
//!   a suite that is always used as a unit. Per-crate errors would be more
//!   granular but add friction with no practical benefit for this use-case.

use core::fmt;

/// Errors that can arise from Lupine PQC operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Key generation failed (e.g. RNG failure or parameter rejection).
    KeyGeneration,
    /// Encapsulation failed.
    Encapsulation,
    /// Decapsulation failed (ciphertext invalid or key mismatch).
    Decapsulation,
    /// Signing operation failed.
    Signing,
    /// Signature verification failed.
    Verification,
    /// A key was structurally invalid (wrong length, bad encoding, etc.).
    InvalidKey,
    /// A parameter value was out of range or unsupported.
    InvalidParameter,
    /// Serialization or deserialization failed, with a descriptive message.
    Serialization(SerializationError),
}

/// Detail for serialization failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerializationError {
    /// Human-readable description of what went wrong.
    pub message: &'static str,
}

impl fmt::Display for SerializationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::KeyGeneration => write!(f, "key generation failed"),
            Error::Encapsulation => write!(f, "encapsulation failed"),
            Error::Decapsulation => write!(f, "decapsulation failed"),
            Error::Signing => write!(f, "signing failed"),
            Error::Verification => write!(f, "signature verification failed"),
            Error::InvalidKey => write!(f, "invalid key"),
            Error::InvalidParameter => write!(f, "invalid parameter"),
            Error::Serialization(e) => write!(f, "serialization error: {}", e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Convenience alias used throughout the Lupine crates.
pub type Result<T> = core::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_variants() {
        assert_eq!(Error::KeyGeneration.to_string(), "key generation failed");
        assert_eq!(Error::Encapsulation.to_string(), "encapsulation failed");
        assert_eq!(Error::Decapsulation.to_string(), "decapsulation failed");
        assert_eq!(Error::Signing.to_string(), "signing failed");
        assert_eq!(
            Error::Verification.to_string(),
            "signature verification failed"
        );
        assert_eq!(Error::InvalidKey.to_string(), "invalid key");
        assert_eq!(Error::InvalidParameter.to_string(), "invalid parameter");
    }

    #[test]
    fn serialization_error_display() {
        let e = Error::Serialization(SerializationError { message: "bad DER" });
        assert_eq!(e.to_string(), "serialization error: bad DER");
    }

    #[test]
    fn error_is_clone_and_eq() {
        let e = Error::InvalidKey;
        assert_eq!(e.clone(), e);
    }
}
