//! Shared concrete types for the Lupine PQC suite.
//!
//! This module provides the `SharedSecret` newtype, which wraps the raw bytes
//! produced by a KEM decapsulation. Sensitive material is zeroed on drop via
//! the `Zeroize` trait, and `Debug` output is intentionally redacted to
//! prevent accidental secret exposure in logs.
//!
//! @decision DEC-CORE-004
//! @title SharedSecret as opaque newtype vs. type alias
//! @status accepted
//! @rationale A newtype (not a type alias) is required to implement custom
//!   Debug (redacting the bytes), Zeroize-on-drop, and to prevent accidental
//!   use of the raw `Vec<u8>` in a context that expects a structured secret. A
//!   type alias would be transparent to the type system and allow callers to
//!   bypass the redacted Debug impl. The newtype costs one extra line at each
//!   call site (.0 or .as_bytes()) but provides meaningful safety guarantees.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// A shared secret produced by a KEM encapsulation or decapsulation.
///
/// The inner bytes are zeroed when the value is dropped. `Debug` output
/// is redacted — the bytes are never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret(Vec<u8>);

impl SharedSecret {
    /// Wrap raw bytes as a `SharedSecret`.
    ///
    /// The caller is responsible for ensuring `bytes` is a cryptographically
    /// valid shared secret (correct length, uniformly random, etc.).
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrow the raw secret bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return the length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the secret is empty (should never happen in practice).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Consume `self` and return the inner bytes.
    ///
    /// Prefer `as_bytes()` to avoid giving up zeroize-on-drop protection.
    /// This method bypasses the `ZeroizeOnDrop` destructor via
    /// `ManuallyDrop` — the caller is responsible for clearing the returned
    /// bytes when done.
    pub fn into_bytes(self) -> Vec<u8> {
        // ZeroizeOnDrop is derived, so we cannot move out of `self` directly.
        // ManuallyDrop suppresses the drop, letting us move the inner Vec out.
        let mut md = core::mem::ManuallyDrop::new(self);
        core::mem::take(&mut md.0)
    }
}

/// Redacted: never prints the actual secret bytes.
impl fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SharedSecret")
            .field("len", &self.0.len())
            .field("bytes", &"<redacted>")
            .finish()
    }
}

impl PartialEq for SharedSecret {
    fn eq(&self, other: &Self) -> bool {
        // Constant-time comparison is not required here — SharedSecret equality
        // is only used in tests. If timing-safe comparison were needed the
        // caller should use a dedicated function (e.g. subtle::ConstantTimeEq).
        self.0 == other.0
    }
}

impl Eq for SharedSecret {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let s = SharedSecret::new(vec![0xde, 0xad, 0xbe, 0xef]);
        let dbg = format!("{:?}", s);
        assert!(
            dbg.contains("<redacted>"),
            "debug output must be redacted: {}",
            dbg
        );
        assert!(
            !dbg.contains("de"),
            "raw bytes must not appear in debug output"
        );
    }

    #[test]
    fn as_bytes_roundtrip() {
        let bytes = vec![1u8, 2, 3, 4];
        let s = SharedSecret::new(bytes.clone());
        assert_eq!(s.as_bytes(), bytes.as_slice());
        assert_eq!(s.len(), 4);
        assert!(!s.is_empty());
    }

    #[test]
    fn equality() {
        let a = SharedSecret::new(vec![1, 2, 3]);
        let b = SharedSecret::new(vec![1, 2, 3]);
        let c = SharedSecret::new(vec![4, 5, 6]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }
}
