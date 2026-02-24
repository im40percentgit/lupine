//! Security level taxonomy for the Lupine PQC suite.
//!
//! NIST defines five security categories for post-quantum algorithms.
//! This module provides a common enum used across KEM and signature
//! algorithm parameter sets to express their claimed security level.
//!
//! @decision DEC-CORE-002
//! @title Five-level SecurityLevel enum vs. integer or two-level scheme
//! @status accepted
//! @rationale NIST specifies five distinct security categories (not just
//!   "strong" vs "fast"). Representing all five makes it possible to select
//!   algorithms by category programmatically and ensures API consumers cannot
//!   conflate, e.g., Level1 (AES-128 equivalent) with Level3 (AES-192). An
//!   integer newtype would lose the named-variant ergonomics that make match
//!   exhaustive checks useful.

/// NIST post-quantum security categories.
///
/// Each level corresponds to a classical security target:
/// - Level1 ≈ AES-128
/// - Level2 ≈ SHA-256
/// - Level3 ≈ AES-192
/// - Level4 ≈ SHA-384
/// - Level5 ≈ AES-256
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SecurityLevel {
    /// Category 1: security at least as hard as AES-128 key search.
    Level1,
    /// Category 2: security at least as hard as SHA-256 collision search.
    Level2,
    /// Category 3: security at least as hard as AES-192 key search.
    Level3,
    /// Category 4: security at least as hard as SHA-384 collision search.
    Level4,
    /// Category 5: security at least as hard as AES-256 key search.
    Level5,
}

impl SecurityLevel {
    /// Return the NIST category number (1–5).
    pub fn as_number(self) -> u8 {
        match self {
            SecurityLevel::Level1 => 1,
            SecurityLevel::Level2 => 2,
            SecurityLevel::Level3 => 3,
            SecurityLevel::Level4 => 4,
            SecurityLevel::Level5 => 5,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordering() {
        assert!(SecurityLevel::Level1 < SecurityLevel::Level3);
        assert!(SecurityLevel::Level5 > SecurityLevel::Level2);
    }

    #[test]
    fn as_number() {
        assert_eq!(SecurityLevel::Level1.as_number(), 1);
        assert_eq!(SecurityLevel::Level5.as_number(), 5);
    }
}
