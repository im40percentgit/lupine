//! CLI algorithm identifier enum for the Lupine PQC suite.
//!
//! `CliAlgorithm` is a flat 24-variant enum covering all supported parameter
//! sets: ML-KEM (3), hybrid X25519+ML-KEM (3), ML-DSA (3), hybrid
//! Ed25519+ML-DSA (3), and SLH-DSA (12). It bridges the CLI's string-based
//! algorithm selection with the typed enums in `lupine_core` and the composite
//! variant enums in `lupine_serial::composite`.
//!
//! @decision DEC-CLI-001
//! @title Single flat CliAlgorithm enum for all 24 parameter sets
//! @status accepted
//! @rationale The CLI must accept a single `--algorithm` flag across all
//!   subcommands. A flat enum with `is_kem()` / `is_sign()` guards lets clap
//!   parse one type and dispatch to the correct crypto operation, rather than
//!   having separate per-subcommand enums. The mapping methods (`to_kem_algorithm`,
//!   etc.) convert to the strongly-typed core enums at the dispatch boundary,
//!   keeping the type-safety guarantees intact inside the crypto layer.

use std::str::FromStr;

use lupine_core::{KemAlgorithm, SignAlgorithm};
use lupine_serial::composite::{CompositeKemVariant, CompositeSignVariant};

/// A CLI-level algorithm selector covering all 24 Lupine parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CliAlgorithm {
    // --- Pure ML-KEM ---
    MlKem512,
    MlKem768,
    MlKem1024,

    // --- Hybrid X25519 + ML-KEM ---
    X25519MlKem512,
    X25519MlKem768,
    X25519MlKem1024,

    // --- Pure ML-DSA ---
    MlDsa44,
    MlDsa65,
    MlDsa87,

    // --- Hybrid Ed25519 + ML-DSA ---
    Ed25519MlDsa44,
    Ed25519MlDsa65,
    Ed25519MlDsa87,

    // --- SLH-DSA SHA-2 variants ---
    SlhDsaSha2128s,
    SlhDsaSha2128f,
    SlhDsaSha2192s,
    SlhDsaSha2192f,
    SlhDsaSha2256s,
    SlhDsaSha2256f,

    // --- SLH-DSA SHAKE variants ---
    SlhDsaShake128s,
    SlhDsaShake128f,
    SlhDsaShake192s,
    SlhDsaShake192f,
    SlhDsaShake256s,
    SlhDsaShake256f,
}

impl CliAlgorithm {
    /// Returns true if this is a KEM algorithm (pure or hybrid).
    pub fn is_kem(self) -> bool {
        matches!(
            self,
            CliAlgorithm::MlKem512
                | CliAlgorithm::MlKem768
                | CliAlgorithm::MlKem1024
                | CliAlgorithm::X25519MlKem512
                | CliAlgorithm::X25519MlKem768
                | CliAlgorithm::X25519MlKem1024
        )
    }

    /// Returns true if this is a pure (non-hybrid) KEM algorithm.
    pub fn is_pure_kem(self) -> bool {
        matches!(
            self,
            CliAlgorithm::MlKem512 | CliAlgorithm::MlKem768 | CliAlgorithm::MlKem1024
        )
    }

    /// Returns true if this is a hybrid KEM algorithm (X25519+ML-KEM).
    pub fn is_hybrid_kem(self) -> bool {
        matches!(
            self,
            CliAlgorithm::X25519MlKem512
                | CliAlgorithm::X25519MlKem768
                | CliAlgorithm::X25519MlKem1024
        )
    }

    /// Returns true if this is a signature algorithm (pure or hybrid).
    pub fn is_sign(self) -> bool {
        !self.is_kem()
    }

    /// Returns true if this is a hybrid sign algorithm (Ed25519+ML-DSA).
    pub fn is_hybrid_sign(self) -> bool {
        matches!(
            self,
            CliAlgorithm::Ed25519MlDsa44
                | CliAlgorithm::Ed25519MlDsa65
                | CliAlgorithm::Ed25519MlDsa87
        )
    }

    /// Returns true if this is a pure ML-DSA algorithm.
    pub fn is_mldsa(self) -> bool {
        matches!(
            self,
            CliAlgorithm::MlDsa44 | CliAlgorithm::MlDsa65 | CliAlgorithm::MlDsa87
        )
    }

    /// Returns true if this is an SLH-DSA algorithm.
    // Used in tests; allow dead_code for production codepath lint.
    #[allow(dead_code)]
    pub fn is_slhdsa(self) -> bool {
        !self.is_kem() && !self.is_mldsa() && !self.is_hybrid_sign()
    }

    /// Map this KEM variant to the `lupine_core::KemAlgorithm` enum.
    ///
    /// Returns `None` for hybrid KEM variants (use `to_composite_kem_variant`
    /// instead) and for non-KEM algorithms.
    pub fn to_kem_algorithm(self) -> Option<KemAlgorithm> {
        match self {
            CliAlgorithm::MlKem512 => Some(KemAlgorithm::MlKem512),
            CliAlgorithm::MlKem768 => Some(KemAlgorithm::MlKem768),
            CliAlgorithm::MlKem1024 => Some(KemAlgorithm::MlKem1024),
            _ => None,
        }
    }

    /// Map this sign variant to the `lupine_core::SignAlgorithm` enum.
    ///
    /// Returns `None` for hybrid sign variants (use `to_composite_sign_variant`
    /// instead) and for non-sign algorithms.
    pub fn to_sign_algorithm(self) -> Option<SignAlgorithm> {
        match self {
            CliAlgorithm::MlDsa44 => Some(SignAlgorithm::MlDsa44),
            CliAlgorithm::MlDsa65 => Some(SignAlgorithm::MlDsa65),
            CliAlgorithm::MlDsa87 => Some(SignAlgorithm::MlDsa87),
            CliAlgorithm::SlhDsaSha2128s => Some(SignAlgorithm::SlhDsaSha2128s),
            CliAlgorithm::SlhDsaSha2128f => Some(SignAlgorithm::SlhDsaSha2128f),
            CliAlgorithm::SlhDsaSha2192s => Some(SignAlgorithm::SlhDsaSha2192s),
            CliAlgorithm::SlhDsaSha2192f => Some(SignAlgorithm::SlhDsaSha2192f),
            CliAlgorithm::SlhDsaSha2256s => Some(SignAlgorithm::SlhDsaSha2256s),
            CliAlgorithm::SlhDsaSha2256f => Some(SignAlgorithm::SlhDsaSha2256f),
            CliAlgorithm::SlhDsaShake128s => Some(SignAlgorithm::SlhDsaShake128s),
            CliAlgorithm::SlhDsaShake128f => Some(SignAlgorithm::SlhDsaShake128f),
            CliAlgorithm::SlhDsaShake192s => Some(SignAlgorithm::SlhDsaShake192s),
            CliAlgorithm::SlhDsaShake192f => Some(SignAlgorithm::SlhDsaShake192f),
            CliAlgorithm::SlhDsaShake256s => Some(SignAlgorithm::SlhDsaShake256s),
            CliAlgorithm::SlhDsaShake256f => Some(SignAlgorithm::SlhDsaShake256f),
            _ => None,
        }
    }

    /// Map a hybrid KEM variant to its `CompositeKemVariant`.
    pub fn to_composite_kem_variant(self) -> Option<CompositeKemVariant> {
        match self {
            CliAlgorithm::X25519MlKem512 => Some(CompositeKemVariant::X25519MlKem512),
            CliAlgorithm::X25519MlKem768 => Some(CompositeKemVariant::X25519MlKem768),
            CliAlgorithm::X25519MlKem1024 => Some(CompositeKemVariant::X25519MlKem1024),
            _ => None,
        }
    }

    /// Map a hybrid sign variant to its `CompositeSignVariant`.
    pub fn to_composite_sign_variant(self) -> Option<CompositeSignVariant> {
        match self {
            CliAlgorithm::Ed25519MlDsa44 => Some(CompositeSignVariant::Ed25519MlDsa44),
            CliAlgorithm::Ed25519MlDsa65 => Some(CompositeSignVariant::Ed25519MlDsa65),
            CliAlgorithm::Ed25519MlDsa87 => Some(CompositeSignVariant::Ed25519MlDsa87),
            _ => None,
        }
    }

    /// Convert from `KemAlgorithm` (non-hybrid only).
    pub fn from_kem_algorithm(alg: KemAlgorithm) -> Self {
        match alg {
            KemAlgorithm::MlKem512 => CliAlgorithm::MlKem512,
            KemAlgorithm::MlKem768 => CliAlgorithm::MlKem768,
            KemAlgorithm::MlKem1024 => CliAlgorithm::MlKem1024,
        }
    }

    /// Convert from `SignAlgorithm`.
    pub fn from_sign_algorithm(alg: SignAlgorithm) -> Self {
        match alg {
            SignAlgorithm::MlDsa44 => CliAlgorithm::MlDsa44,
            SignAlgorithm::MlDsa65 => CliAlgorithm::MlDsa65,
            SignAlgorithm::MlDsa87 => CliAlgorithm::MlDsa87,
            SignAlgorithm::SlhDsaSha2128s => CliAlgorithm::SlhDsaSha2128s,
            SignAlgorithm::SlhDsaSha2128f => CliAlgorithm::SlhDsaSha2128f,
            SignAlgorithm::SlhDsaSha2192s => CliAlgorithm::SlhDsaSha2192s,
            SignAlgorithm::SlhDsaSha2192f => CliAlgorithm::SlhDsaSha2192f,
            SignAlgorithm::SlhDsaSha2256s => CliAlgorithm::SlhDsaSha2256s,
            SignAlgorithm::SlhDsaSha2256f => CliAlgorithm::SlhDsaSha2256f,
            SignAlgorithm::SlhDsaShake128s => CliAlgorithm::SlhDsaShake128s,
            SignAlgorithm::SlhDsaShake128f => CliAlgorithm::SlhDsaShake128f,
            SignAlgorithm::SlhDsaShake192s => CliAlgorithm::SlhDsaShake192s,
            SignAlgorithm::SlhDsaShake192f => CliAlgorithm::SlhDsaShake192f,
            SignAlgorithm::SlhDsaShake256s => CliAlgorithm::SlhDsaShake256s,
            SignAlgorithm::SlhDsaShake256f => CliAlgorithm::SlhDsaShake256f,
        }
    }

    /// Convert from `CompositeKemVariant`.
    pub fn from_composite_kem_variant(v: CompositeKemVariant) -> Self {
        match v {
            CompositeKemVariant::X25519MlKem512 => CliAlgorithm::X25519MlKem512,
            CompositeKemVariant::X25519MlKem768 => CliAlgorithm::X25519MlKem768,
            CompositeKemVariant::X25519MlKem1024 => CliAlgorithm::X25519MlKem1024,
        }
    }

    /// Convert from `CompositeSignVariant`.
    pub fn from_composite_sign_variant(v: CompositeSignVariant) -> Self {
        match v {
            CompositeSignVariant::Ed25519MlDsa44 => CliAlgorithm::Ed25519MlDsa44,
            CompositeSignVariant::Ed25519MlDsa65 => CliAlgorithm::Ed25519MlDsa65,
            CompositeSignVariant::Ed25519MlDsa87 => CliAlgorithm::Ed25519MlDsa87,
        }
    }

    /// Known ML-KEM public key sizes (raw bytes) for each pure KEM variant.
    ///
    /// Used by the format layer to detect where the public key ends in a
    /// concatenated pk||sk hybrid secret key blob.
    pub fn hybrid_kem_pk_size(self) -> Option<usize> {
        match self {
            // Hybrid PK = 32 (x25519) + mlkem_pk_size
            CliAlgorithm::X25519MlKem512 => Some(32 + 800),
            CliAlgorithm::X25519MlKem768 => Some(32 + 1184),
            CliAlgorithm::X25519MlKem1024 => Some(32 + 1568),
            _ => None,
        }
    }

    /// All CLI algorithm names in kebab-case, for help text.
    pub fn all_names() -> &'static [&'static str] {
        &[
            "ml-kem-512",
            "ml-kem-768",
            "ml-kem-1024",
            "x25519-ml-kem-512",
            "x25519-ml-kem-768",
            "x25519-ml-kem-1024",
            "ml-dsa-44",
            "ml-dsa-65",
            "ml-dsa-87",
            "ed25519-ml-dsa-44",
            "ed25519-ml-dsa-65",
            "ed25519-ml-dsa-87",
            "slh-dsa-sha2-128s",
            "slh-dsa-sha2-128f",
            "slh-dsa-sha2-192s",
            "slh-dsa-sha2-192f",
            "slh-dsa-sha2-256s",
            "slh-dsa-sha2-256f",
            "slh-dsa-shake-128s",
            "slh-dsa-shake-128f",
            "slh-dsa-shake-192s",
            "slh-dsa-shake-192f",
            "slh-dsa-shake-256s",
            "slh-dsa-shake-256f",
        ]
    }
}

impl std::fmt::Display for CliAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            CliAlgorithm::MlKem512 => "ml-kem-512",
            CliAlgorithm::MlKem768 => "ml-kem-768",
            CliAlgorithm::MlKem1024 => "ml-kem-1024",
            CliAlgorithm::X25519MlKem512 => "x25519-ml-kem-512",
            CliAlgorithm::X25519MlKem768 => "x25519-ml-kem-768",
            CliAlgorithm::X25519MlKem1024 => "x25519-ml-kem-1024",
            CliAlgorithm::MlDsa44 => "ml-dsa-44",
            CliAlgorithm::MlDsa65 => "ml-dsa-65",
            CliAlgorithm::MlDsa87 => "ml-dsa-87",
            CliAlgorithm::Ed25519MlDsa44 => "ed25519-ml-dsa-44",
            CliAlgorithm::Ed25519MlDsa65 => "ed25519-ml-dsa-65",
            CliAlgorithm::Ed25519MlDsa87 => "ed25519-ml-dsa-87",
            CliAlgorithm::SlhDsaSha2128s => "slh-dsa-sha2-128s",
            CliAlgorithm::SlhDsaSha2128f => "slh-dsa-sha2-128f",
            CliAlgorithm::SlhDsaSha2192s => "slh-dsa-sha2-192s",
            CliAlgorithm::SlhDsaSha2192f => "slh-dsa-sha2-192f",
            CliAlgorithm::SlhDsaSha2256s => "slh-dsa-sha2-256s",
            CliAlgorithm::SlhDsaSha2256f => "slh-dsa-sha2-256f",
            CliAlgorithm::SlhDsaShake128s => "slh-dsa-shake-128s",
            CliAlgorithm::SlhDsaShake128f => "slh-dsa-shake-128f",
            CliAlgorithm::SlhDsaShake192s => "slh-dsa-shake-192s",
            CliAlgorithm::SlhDsaShake192f => "slh-dsa-shake-192f",
            CliAlgorithm::SlhDsaShake256s => "slh-dsa-shake-256s",
            CliAlgorithm::SlhDsaShake256f => "slh-dsa-shake-256f",
        };
        f.write_str(s)
    }
}

impl FromStr for CliAlgorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ml-kem-512" => Ok(CliAlgorithm::MlKem512),
            "ml-kem-768" => Ok(CliAlgorithm::MlKem768),
            "ml-kem-1024" => Ok(CliAlgorithm::MlKem1024),
            "x25519-ml-kem-512" => Ok(CliAlgorithm::X25519MlKem512),
            "x25519-ml-kem-768" => Ok(CliAlgorithm::X25519MlKem768),
            "x25519-ml-kem-1024" => Ok(CliAlgorithm::X25519MlKem1024),
            "ml-dsa-44" => Ok(CliAlgorithm::MlDsa44),
            "ml-dsa-65" => Ok(CliAlgorithm::MlDsa65),
            "ml-dsa-87" => Ok(CliAlgorithm::MlDsa87),
            "ed25519-ml-dsa-44" => Ok(CliAlgorithm::Ed25519MlDsa44),
            "ed25519-ml-dsa-65" => Ok(CliAlgorithm::Ed25519MlDsa65),
            "ed25519-ml-dsa-87" => Ok(CliAlgorithm::Ed25519MlDsa87),
            "slh-dsa-sha2-128s" => Ok(CliAlgorithm::SlhDsaSha2128s),
            "slh-dsa-sha2-128f" => Ok(CliAlgorithm::SlhDsaSha2128f),
            "slh-dsa-sha2-192s" => Ok(CliAlgorithm::SlhDsaSha2192s),
            "slh-dsa-sha2-192f" => Ok(CliAlgorithm::SlhDsaSha2192f),
            "slh-dsa-sha2-256s" => Ok(CliAlgorithm::SlhDsaSha2256s),
            "slh-dsa-sha2-256f" => Ok(CliAlgorithm::SlhDsaSha2256f),
            "slh-dsa-shake-128s" => Ok(CliAlgorithm::SlhDsaShake128s),
            "slh-dsa-shake-128f" => Ok(CliAlgorithm::SlhDsaShake128f),
            "slh-dsa-shake-192s" => Ok(CliAlgorithm::SlhDsaShake192s),
            "slh-dsa-shake-192f" => Ok(CliAlgorithm::SlhDsaShake192f),
            "slh-dsa-shake-256s" => Ok(CliAlgorithm::SlhDsaShake256s),
            "slh-dsa-shake-256f" => Ok(CliAlgorithm::SlhDsaShake256f),
            other => Err(format!(
                "unknown algorithm '{}'; valid choices: {}",
                other,
                CliAlgorithm::all_names().join(", ")
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_roundtrip_all() {
        for name in CliAlgorithm::all_names() {
            let alg: CliAlgorithm = name.parse().expect("parse failed");
            assert_eq!(alg.to_string(), *name, "display roundtrip failed for {name}");
        }
    }

    #[test]
    fn category_is_kem() {
        assert!(CliAlgorithm::MlKem512.is_kem());
        assert!(CliAlgorithm::X25519MlKem768.is_kem());
        assert!(!CliAlgorithm::MlDsa65.is_kem());
    }

    #[test]
    fn category_is_sign() {
        assert!(CliAlgorithm::MlDsa44.is_sign());
        assert!(CliAlgorithm::Ed25519MlDsa65.is_sign());
        assert!(CliAlgorithm::SlhDsaSha2128s.is_sign());
        assert!(!CliAlgorithm::MlKem512.is_sign());
    }

    #[test]
    fn hybrid_kem_flags() {
        assert!(CliAlgorithm::X25519MlKem512.is_hybrid_kem());
        assert!(!CliAlgorithm::MlKem512.is_hybrid_kem());
    }

    #[test]
    fn hybrid_sign_flags() {
        assert!(CliAlgorithm::Ed25519MlDsa44.is_hybrid_sign());
        assert!(!CliAlgorithm::MlDsa44.is_hybrid_sign());
    }

    #[test]
    fn slhdsa_flag() {
        assert!(CliAlgorithm::SlhDsaSha2128s.is_slhdsa());
        assert!(CliAlgorithm::SlhDsaShake256f.is_slhdsa());
        assert!(!CliAlgorithm::MlDsa65.is_slhdsa());
    }

    #[test]
    fn to_kem_algorithm_mapping() {
        assert_eq!(CliAlgorithm::MlKem768.to_kem_algorithm(), Some(KemAlgorithm::MlKem768));
        assert_eq!(CliAlgorithm::X25519MlKem768.to_kem_algorithm(), None);
        assert_eq!(CliAlgorithm::MlDsa65.to_kem_algorithm(), None);
    }

    #[test]
    fn to_sign_algorithm_mapping() {
        assert_eq!(CliAlgorithm::MlDsa44.to_sign_algorithm(), Some(SignAlgorithm::MlDsa44));
        assert_eq!(CliAlgorithm::SlhDsaSha2128f.to_sign_algorithm(), Some(SignAlgorithm::SlhDsaSha2128f));
        assert_eq!(CliAlgorithm::Ed25519MlDsa44.to_sign_algorithm(), None);
        assert_eq!(CliAlgorithm::MlKem512.to_sign_algorithm(), None);
    }

    #[test]
    fn hybrid_kem_pk_sizes() {
        assert_eq!(CliAlgorithm::X25519MlKem512.hybrid_kem_pk_size(), Some(832));
        assert_eq!(CliAlgorithm::X25519MlKem768.hybrid_kem_pk_size(), Some(1216));
        assert_eq!(CliAlgorithm::X25519MlKem1024.hybrid_kem_pk_size(), Some(1600));
        assert_eq!(CliAlgorithm::MlKem768.hybrid_kem_pk_size(), None);
    }

    #[test]
    fn unknown_algorithm_rejected() {
        assert!("ml-kem-9999".parse::<CliAlgorithm>().is_err());
    }
}
