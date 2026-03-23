//! Algorithm parameter-set enumerations for the Lupine PQC suite.
//!
//! Provides `KemAlgorithm` and `SignAlgorithm` enums that identify every
//! standardised parameter set supported by Lupine, along with metadata such
//! as the NIST security category for each set.
//!
//! @decision DEC-CORE-003
//! @title Enum-per-algorithm-family vs. a single Algorithm enum
//! @status accepted
//! @rationale Separating KEM and signature algorithms into two enums prevents
//!   callers from accidentally supplying a KEM identifier where a signature
//!   identifier is expected (and vice versa). The type system enforces the
//!   distinction at compile time with zero runtime overhead. A single flat
//!   enum would be simpler but would require runtime guards everywhere the
//!   distinction matters.

use crate::traits::SecurityLevel;

/// ML-KEM (FIPS 203) parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemAlgorithm {
    /// ML-KEM-512 — NIST security category 1.
    MlKem512,
    /// ML-KEM-768 — NIST security category 3.
    MlKem768,
    /// ML-KEM-1024 — NIST security category 5.
    MlKem1024,
}

impl KemAlgorithm {
    /// Return the NIST security level for this parameter set.
    pub fn security_level(self) -> SecurityLevel {
        match self {
            KemAlgorithm::MlKem512 => SecurityLevel::Level1,
            KemAlgorithm::MlKem768 => SecurityLevel::Level3,
            KemAlgorithm::MlKem1024 => SecurityLevel::Level5,
        }
    }
}

/// ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) parameter sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignAlgorithm {
    // --- ML-DSA (FIPS 204) ---
    /// ML-DSA-44 — NIST security category 2.
    MlDsa44,
    /// ML-DSA-65 — NIST security category 3.
    MlDsa65,
    /// ML-DSA-87 — NIST security category 5.
    MlDsa87,

    // --- SLH-DSA (FIPS 205) — SHA-2 variants ---
    /// SLH-DSA-SHA2-128s — category 1, small signatures.
    SlhDsaSha2128s,
    /// SLH-DSA-SHA2-128f — category 1, fast signing.
    SlhDsaSha2128f,
    /// SLH-DSA-SHA2-192s — category 3, small signatures.
    SlhDsaSha2192s,
    /// SLH-DSA-SHA2-192f — category 3, fast signing.
    SlhDsaSha2192f,
    /// SLH-DSA-SHA2-256s — category 5, small signatures.
    SlhDsaSha2256s,
    /// SLH-DSA-SHA2-256f — category 5, fast signing.
    SlhDsaSha2256f,

    // --- SLH-DSA (FIPS 205) — SHAKE variants ---
    /// SLH-DSA-SHAKE-128s — category 1, small signatures.
    SlhDsaShake128s,
    /// SLH-DSA-SHAKE-128f — category 1, fast signing.
    SlhDsaShake128f,
    /// SLH-DSA-SHAKE-192s — category 3, small signatures.
    SlhDsaShake192s,
    /// SLH-DSA-SHAKE-192f — category 3, fast signing.
    SlhDsaShake192f,
    /// SLH-DSA-SHAKE-256s — category 5, small signatures.
    SlhDsaShake256s,
    /// SLH-DSA-SHAKE-256f — category 5, fast signing.
    SlhDsaShake256f,
}

impl SignAlgorithm {
    /// Return the NIST security level for this parameter set.
    pub fn security_level(self) -> SecurityLevel {
        match self {
            SignAlgorithm::MlDsa44 => SecurityLevel::Level2,
            SignAlgorithm::MlDsa65 => SecurityLevel::Level3,
            SignAlgorithm::MlDsa87 => SecurityLevel::Level5,

            SignAlgorithm::SlhDsaSha2128s | SignAlgorithm::SlhDsaSha2128f => SecurityLevel::Level1,
            SignAlgorithm::SlhDsaSha2192s | SignAlgorithm::SlhDsaSha2192f => SecurityLevel::Level3,
            SignAlgorithm::SlhDsaSha2256s | SignAlgorithm::SlhDsaSha2256f => SecurityLevel::Level5,

            SignAlgorithm::SlhDsaShake128s | SignAlgorithm::SlhDsaShake128f => {
                SecurityLevel::Level1
            }
            SignAlgorithm::SlhDsaShake192s | SignAlgorithm::SlhDsaShake192f => {
                SecurityLevel::Level3
            }
            SignAlgorithm::SlhDsaShake256s | SignAlgorithm::SlhDsaShake256f => {
                SecurityLevel::Level5
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kem_security_levels() {
        assert_eq!(
            KemAlgorithm::MlKem512.security_level(),
            SecurityLevel::Level1
        );
        assert_eq!(
            KemAlgorithm::MlKem768.security_level(),
            SecurityLevel::Level3
        );
        assert_eq!(
            KemAlgorithm::MlKem1024.security_level(),
            SecurityLevel::Level5
        );
    }

    #[test]
    fn mldsa_security_levels() {
        assert_eq!(
            SignAlgorithm::MlDsa44.security_level(),
            SecurityLevel::Level2
        );
        assert_eq!(
            SignAlgorithm::MlDsa65.security_level(),
            SecurityLevel::Level3
        );
        assert_eq!(
            SignAlgorithm::MlDsa87.security_level(),
            SecurityLevel::Level5
        );
    }

    #[test]
    fn slhdsa_security_levels() {
        assert_eq!(
            SignAlgorithm::SlhDsaSha2128s.security_level(),
            SecurityLevel::Level1
        );
        assert_eq!(
            SignAlgorithm::SlhDsaSha2192f.security_level(),
            SecurityLevel::Level3
        );
        assert_eq!(
            SignAlgorithm::SlhDsaShake256s.security_level(),
            SecurityLevel::Level5
        );
    }
}
