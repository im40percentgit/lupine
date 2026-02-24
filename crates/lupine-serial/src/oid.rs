//! OID constants for Lupine PQC algorithm identifiers.
//!
//! Sources:
//! - ML-KEM (FIPS 203): NIST CSOR assignments under 2.16.840.1.101.3.4.4.*
//!   (draft OIDs; may change before final publication)
//! - ML-DSA (FIPS 204): NIST CSOR assignments under 2.16.840.1.101.3.4.3.*
//! - SLH-DSA (FIPS 205): NIST CSOR assignments under 2.16.840.1.101.3.4.3.*
//!   (SLH-DSA OIDs were assigned in early 2024 alongside the standard)
//!
//! All OIDs are encoded as [`der::asn1::ObjectIdentifier`] constants for use in
//! AlgorithmIdentifier structures throughout the serialization layer.
//!
//! @decision DEC-SERIAL-001
//! @title OID source and stability
//! @status accepted
//! @rationale NIST assigned these OIDs in the CSOR registry concurrent with
//!   the FIPS publication. They are final (not draft) for ML-KEM and ML-DSA
//!   as of FIPS 203/204 publication (August 2024). SLH-DSA OIDs under .3.4.3
//!   were also assigned for FIPS 205. Using the real NIST OIDs here (rather
//!   than private arcs) means interoperability with other implementations that
//!   follow the same NIST assignments is possible from day one.

use der::asn1::ObjectIdentifier;
use lupine_core::{KemAlgorithm, SignAlgorithm};

// ---------------------------------------------------------------------------
// ML-KEM OIDs  (FIPS 203 / NIST CSOR 2.16.840.1.101.3.4.4.*)
// ---------------------------------------------------------------------------

/// OID for ML-KEM-512 (NIST CSOR: 2.16.840.1.101.3.4.4.1).
pub const OID_ML_KEM_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.1");

/// OID for ML-KEM-768 (NIST CSOR: 2.16.840.1.101.3.4.4.2).
pub const OID_ML_KEM_768: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.2");

/// OID for ML-KEM-1024 (NIST CSOR: 2.16.840.1.101.3.4.4.3).
pub const OID_ML_KEM_1024: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.4.3");

// ---------------------------------------------------------------------------
// ML-DSA OIDs  (FIPS 204 / NIST CSOR 2.16.840.1.101.3.4.3.*)
// ---------------------------------------------------------------------------

/// OID for ML-DSA-44 (NIST CSOR: 2.16.840.1.101.3.4.3.17).
pub const OID_ML_DSA_44: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.17");

/// OID for ML-DSA-65 (NIST CSOR: 2.16.840.1.101.3.4.3.18).
pub const OID_ML_DSA_65: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.18");

/// OID for ML-DSA-87 (NIST CSOR: 2.16.840.1.101.3.4.3.19).
pub const OID_ML_DSA_87: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.19");

// ---------------------------------------------------------------------------
// SLH-DSA OIDs  (FIPS 205 / NIST CSOR 2.16.840.1.101.3.4.3.*)
// ---------------------------------------------------------------------------
// Assignments from NIST CSOR (published 2024):
//   SHA2 variants:   .20 (128s), .21 (128f), .22 (192s), .23 (192f), .24 (256s), .25 (256f)
//   SHAKE variants:  .26 (128s), .27 (128f), .28 (192s), .29 (192f), .30 (256s), .31 (256f)

/// OID for SLH-DSA-SHA2-128s (NIST CSOR: 2.16.840.1.101.3.4.3.20).
pub const OID_SLH_DSA_SHA2_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.20");

/// OID for SLH-DSA-SHA2-128f (NIST CSOR: 2.16.840.1.101.3.4.3.21).
pub const OID_SLH_DSA_SHA2_128F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.21");

/// OID for SLH-DSA-SHA2-192s (NIST CSOR: 2.16.840.1.101.3.4.3.22).
pub const OID_SLH_DSA_SHA2_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.22");

/// OID for SLH-DSA-SHA2-192f (NIST CSOR: 2.16.840.1.101.3.4.3.23).
pub const OID_SLH_DSA_SHA2_192F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.23");

/// OID for SLH-DSA-SHA2-256s (NIST CSOR: 2.16.840.1.101.3.4.3.24).
pub const OID_SLH_DSA_SHA2_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.24");

/// OID for SLH-DSA-SHA2-256f (NIST CSOR: 2.16.840.1.101.3.4.3.25).
pub const OID_SLH_DSA_SHA2_256F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.25");

/// OID for SLH-DSA-SHAKE-128s (NIST CSOR: 2.16.840.1.101.3.4.3.26).
pub const OID_SLH_DSA_SHAKE_128S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.26");

/// OID for SLH-DSA-SHAKE-128f (NIST CSOR: 2.16.840.1.101.3.4.3.27).
pub const OID_SLH_DSA_SHAKE_128F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.27");

/// OID for SLH-DSA-SHAKE-192s (NIST CSOR: 2.16.840.1.101.3.4.3.28).
pub const OID_SLH_DSA_SHAKE_192S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.28");

/// OID for SLH-DSA-SHAKE-192f (NIST CSOR: 2.16.840.1.101.3.4.3.29).
pub const OID_SLH_DSA_SHAKE_192F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.29");

/// OID for SLH-DSA-SHAKE-256s (NIST CSOR: 2.16.840.1.101.3.4.3.30).
pub const OID_SLH_DSA_SHAKE_256S: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.30");

/// OID for SLH-DSA-SHAKE-256f (NIST CSOR: 2.16.840.1.101.3.4.3.31).
pub const OID_SLH_DSA_SHAKE_256F: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.3.31");

// ---------------------------------------------------------------------------
// Composite hybrid OIDs (private arc — no IETF standard yet)
// ---------------------------------------------------------------------------
// Using the IANA Private Enterprise Number arc 1.3.6.1.4.1.57817 (lupine)
// for composite hybrid types until IETF LAMPS produces final assignments.
// Sub-arcs: .1 = composite KEM, .2 = composite signature

/// OID for Composite X25519+ML-KEM-512 hybrid KEM (Lupine private arc).
pub const OID_HYBRID_KEM_512: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57817.1.1");

/// OID for Composite X25519+ML-KEM-768 hybrid KEM (Lupine private arc).
pub const OID_HYBRID_KEM_768: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57817.1.2");

/// OID for Composite X25519+ML-KEM-1024 hybrid KEM (Lupine private arc).
pub const OID_HYBRID_KEM_1024: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57817.1.3");

/// OID for Composite Ed25519+ML-DSA-44 hybrid signature (Lupine private arc).
pub const OID_HYBRID_SIGN_44: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57817.2.1");

/// OID for Composite Ed25519+ML-DSA-65 hybrid signature (Lupine private arc).
pub const OID_HYBRID_SIGN_65: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57817.2.2");

/// OID for Composite Ed25519+ML-DSA-87 hybrid signature (Lupine private arc).
pub const OID_HYBRID_SIGN_87: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.57817.2.3");

// ---------------------------------------------------------------------------
// Algorithm → OID dispatch
// ---------------------------------------------------------------------------

/// Return the OID for a KEM algorithm's public key.
pub fn oid_for_kem(alg: KemAlgorithm) -> ObjectIdentifier {
    match alg {
        KemAlgorithm::MlKem512 => OID_ML_KEM_512,
        KemAlgorithm::MlKem768 => OID_ML_KEM_768,
        KemAlgorithm::MlKem1024 => OID_ML_KEM_1024,
    }
}

/// Return the OID for a signature algorithm's public/secret key or signature.
pub fn oid_for_sign(alg: SignAlgorithm) -> ObjectIdentifier {
    match alg {
        SignAlgorithm::MlDsa44 => OID_ML_DSA_44,
        SignAlgorithm::MlDsa65 => OID_ML_DSA_65,
        SignAlgorithm::MlDsa87 => OID_ML_DSA_87,
        SignAlgorithm::SlhDsaSha2128s => OID_SLH_DSA_SHA2_128S,
        SignAlgorithm::SlhDsaSha2128f => OID_SLH_DSA_SHA2_128F,
        SignAlgorithm::SlhDsaSha2192s => OID_SLH_DSA_SHA2_192S,
        SignAlgorithm::SlhDsaSha2192f => OID_SLH_DSA_SHA2_192F,
        SignAlgorithm::SlhDsaSha2256s => OID_SLH_DSA_SHA2_256S,
        SignAlgorithm::SlhDsaSha2256f => OID_SLH_DSA_SHA2_256F,
        SignAlgorithm::SlhDsaShake128s => OID_SLH_DSA_SHAKE_128S,
        SignAlgorithm::SlhDsaShake128f => OID_SLH_DSA_SHAKE_128F,
        SignAlgorithm::SlhDsaShake192s => OID_SLH_DSA_SHAKE_192S,
        SignAlgorithm::SlhDsaShake192f => OID_SLH_DSA_SHAKE_192F,
        SignAlgorithm::SlhDsaShake256s => OID_SLH_DSA_SHAKE_256S,
        SignAlgorithm::SlhDsaShake256f => OID_SLH_DSA_SHAKE_256F,
    }
}

/// Resolve an OID back to a [`KemAlgorithm`], if known.
pub fn kem_from_oid(oid: &ObjectIdentifier) -> Option<KemAlgorithm> {
    if *oid == OID_ML_KEM_512 {
        Some(KemAlgorithm::MlKem512)
    } else if *oid == OID_ML_KEM_768 {
        Some(KemAlgorithm::MlKem768)
    } else if *oid == OID_ML_KEM_1024 {
        Some(KemAlgorithm::MlKem1024)
    } else {
        None
    }
}

/// Resolve an OID back to a [`SignAlgorithm`], if known.
pub fn sign_from_oid(oid: &ObjectIdentifier) -> Option<SignAlgorithm> {
    if *oid == OID_ML_DSA_44 {
        Some(SignAlgorithm::MlDsa44)
    } else if *oid == OID_ML_DSA_65 {
        Some(SignAlgorithm::MlDsa65)
    } else if *oid == OID_ML_DSA_87 {
        Some(SignAlgorithm::MlDsa87)
    } else if *oid == OID_SLH_DSA_SHA2_128S {
        Some(SignAlgorithm::SlhDsaSha2128s)
    } else if *oid == OID_SLH_DSA_SHA2_128F {
        Some(SignAlgorithm::SlhDsaSha2128f)
    } else if *oid == OID_SLH_DSA_SHA2_192S {
        Some(SignAlgorithm::SlhDsaSha2192s)
    } else if *oid == OID_SLH_DSA_SHA2_192F {
        Some(SignAlgorithm::SlhDsaSha2192f)
    } else if *oid == OID_SLH_DSA_SHA2_256S {
        Some(SignAlgorithm::SlhDsaSha2256s)
    } else if *oid == OID_SLH_DSA_SHA2_256F {
        Some(SignAlgorithm::SlhDsaSha2256f)
    } else if *oid == OID_SLH_DSA_SHAKE_128S {
        Some(SignAlgorithm::SlhDsaShake128s)
    } else if *oid == OID_SLH_DSA_SHAKE_128F {
        Some(SignAlgorithm::SlhDsaShake128f)
    } else if *oid == OID_SLH_DSA_SHAKE_192S {
        Some(SignAlgorithm::SlhDsaShake192s)
    } else if *oid == OID_SLH_DSA_SHAKE_192F {
        Some(SignAlgorithm::SlhDsaShake192f)
    } else if *oid == OID_SLH_DSA_SHAKE_256S {
        Some(SignAlgorithm::SlhDsaShake256s)
    } else if *oid == OID_SLH_DSA_SHAKE_256F {
        Some(SignAlgorithm::SlhDsaShake256f)
    } else {
        None
    }
}
