//! SubjectPublicKeyInfo (SPKI) encoding for Lupine PQC public keys.
//!
//! Implements RFC 5280 §4.1.2.7 SubjectPublicKeyInfo wrapping:
//!
//! ```text
//! SubjectPublicKeyInfo ::= SEQUENCE {
//!     algorithm   AlgorithmIdentifier,
//!     subjectPublicKey BIT STRING
//! }
//! AlgorithmIdentifier ::= SEQUENCE {
//!     algorithm   OBJECT IDENTIFIER,
//!     parameters  NULL OPTIONAL
//! }
//! ```
//!
//! The key difference from the simpler `KeyInfo` in `der.rs` is that
//! `subjectPublicKey` is a BIT STRING (with a leading zero-count byte),
//! not an OCTET STRING. This is the format used for public keys in X.509
//! certificates and CSRs.
//!
//! @decision DEC-SERIAL-004
//! @title Manual SPKI encoder vs spki crate
//! @status accepted
//! @rationale The `spki` crate (which would provide this automatically) is at
//!   version `0.8.0-rc.4` — a release candidate with no stable guarantee. Taking
//!   an RC dependency in a library would force all downstream consumers onto the
//!   same RC. The SPKI structure is simple enough (two nested sequences, one OID,
//!   one BIT STRING) that a manual implementation in ~80 lines is safer and more
//!   maintainable. When `spki` stabilises we can delegate to it and remove this
//!   module with no API change (same function signatures, same output bytes).

extern crate alloc;

use alloc::vec::Vec;

use der::{
    Decode, Encode, Sequence,
    asn1::{BitString, ObjectIdentifier},
};
use lupine_core::{Error, KemAlgorithm, Result, SerializationError, SignAlgorithm};

use crate::oid::{kem_from_oid, oid_for_kem, oid_for_sign, sign_from_oid};

// ---------------------------------------------------------------------------
// Internal ASN.1 structures
// ---------------------------------------------------------------------------

/// `AlgorithmIdentifier` as used inside SPKI.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SpkiAlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<()>,
}

/// `SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct SubjectPublicKeyInfo {
    pub algorithm: SpkiAlgorithmIdentifier,
    pub subject_public_key: BitString,
}

// ---------------------------------------------------------------------------
// KEM SPKI
// ---------------------------------------------------------------------------

/// Encode a KEM public key as a SubjectPublicKeyInfo DER blob.
///
/// The resulting bytes can be placed directly in an X.509 certificate's
/// `subjectPublicKeyInfo` field.
pub fn encode_kem_spki(alg: KemAlgorithm, key_bytes: &[u8]) -> Result<Vec<u8>> {
    let spki = SubjectPublicKeyInfo {
        algorithm: SpkiAlgorithmIdentifier {
            algorithm: oid_for_kem(alg),
            parameters: None,
        },
        subject_public_key: BitString::new(0, key_bytes)
            .map_err(|_| ser_err("key too large for SPKI BIT STRING"))?,
    };
    spki.to_der().map_err(|_| ser_err("SPKI DER encoding failed"))
}

/// Decode a KEM public key from a SubjectPublicKeyInfo DER blob.
pub fn decode_kem_spki(der_bytes: &[u8]) -> Result<(KemAlgorithm, Vec<u8>)> {
    let spki = SubjectPublicKeyInfo::from_der(der_bytes)
        .map_err(|_| ser_err("invalid SPKI DER for KEM key"))?;
    let alg = kem_from_oid(&spki.algorithm.algorithm)
        .ok_or_else(|| ser_err("unknown KEM OID in SPKI"))?;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| ser_err("SPKI BIT STRING has unused bits"))?
        .to_vec();
    Ok((alg, key_bytes))
}

// ---------------------------------------------------------------------------
// Signature algorithm SPKI
// ---------------------------------------------------------------------------

/// Encode a signature verifying key as a SubjectPublicKeyInfo DER blob.
pub fn encode_sign_spki(alg: SignAlgorithm, key_bytes: &[u8]) -> Result<Vec<u8>> {
    let spki = SubjectPublicKeyInfo {
        algorithm: SpkiAlgorithmIdentifier {
            algorithm: oid_for_sign(alg),
            parameters: None,
        },
        subject_public_key: BitString::new(0, key_bytes)
            .map_err(|_| ser_err("key too large for SPKI BIT STRING"))?,
    };
    spki.to_der().map_err(|_| ser_err("SPKI DER encoding failed"))
}

/// Decode a signature verifying key from a SubjectPublicKeyInfo DER blob.
pub fn decode_sign_spki(der_bytes: &[u8]) -> Result<(SignAlgorithm, Vec<u8>)> {
    let spki = SubjectPublicKeyInfo::from_der(der_bytes)
        .map_err(|_| ser_err("invalid SPKI DER for sign key"))?;
    let alg = sign_from_oid(&spki.algorithm.algorithm)
        .ok_or_else(|| ser_err("unknown signature OID in SPKI"))?;
    let key_bytes = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| ser_err("SPKI BIT STRING has unused bits"))?
        .to_vec();
    Ok((alg, key_bytes))
}

// ---------------------------------------------------------------------------
// Shared helper
// ---------------------------------------------------------------------------

fn ser_err(message: &'static str) -> Error {
    Error::Serialization(SerializationError { message })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const FAKE_KEY: &[u8] = b"fake_public_key_bytes_for_spki_test";

    #[test]
    fn kem_spki_roundtrip_512() {
        let der = encode_kem_spki(KemAlgorithm::MlKem512, FAKE_KEY).unwrap();
        let (alg, key) = decode_kem_spki(&der).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem512);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn kem_spki_roundtrip_768() {
        let der = encode_kem_spki(KemAlgorithm::MlKem768, FAKE_KEY).unwrap();
        let (alg, key) = decode_kem_spki(&der).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem768);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn kem_spki_roundtrip_1024() {
        let der = encode_kem_spki(KemAlgorithm::MlKem1024, FAKE_KEY).unwrap();
        let (alg, key) = decode_kem_spki(&der).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem1024);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_spki_roundtrip_ml_dsa_44() {
        let der = encode_sign_spki(SignAlgorithm::MlDsa44, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_spki(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa44);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_spki_roundtrip_ml_dsa_65() {
        let der = encode_sign_spki(SignAlgorithm::MlDsa65, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_spki(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa65);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_spki_roundtrip_ml_dsa_87() {
        let der = encode_sign_spki(SignAlgorithm::MlDsa87, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_spki(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa87);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_spki_roundtrip_slh_dsa_sha2_128s() {
        let der = encode_sign_spki(SignAlgorithm::SlhDsaSha2128s, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_spki(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::SlhDsaSha2128s);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_spki_roundtrip_slh_dsa_shake_256f() {
        let der = encode_sign_spki(SignAlgorithm::SlhDsaShake256f, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_spki(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::SlhDsaShake256f);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn spki_differs_from_plain_der() {
        // SPKI (BIT STRING) bytes must differ from plain DER (OCTET STRING).
        use crate::der::encode_kem_public_key_der;
        let spki_der = encode_kem_spki(KemAlgorithm::MlKem512, FAKE_KEY).unwrap();
        let key_der = encode_kem_public_key_der(KemAlgorithm::MlKem512, FAKE_KEY).unwrap();
        assert_ne!(spki_der, key_der);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_kem_spki(b"not der").is_err());
        assert!(decode_sign_spki(b"\x00\x00").is_err());
    }

    #[test]
    fn all_slh_dsa_variants_spki_roundtrip() {
        let variants = [
            SignAlgorithm::SlhDsaSha2128s,
            SignAlgorithm::SlhDsaSha2128f,
            SignAlgorithm::SlhDsaSha2192s,
            SignAlgorithm::SlhDsaSha2192f,
            SignAlgorithm::SlhDsaSha2256s,
            SignAlgorithm::SlhDsaSha2256f,
            SignAlgorithm::SlhDsaShake128s,
            SignAlgorithm::SlhDsaShake128f,
            SignAlgorithm::SlhDsaShake192s,
            SignAlgorithm::SlhDsaShake192f,
            SignAlgorithm::SlhDsaShake256s,
            SignAlgorithm::SlhDsaShake256f,
        ];
        for variant in variants {
            let der = encode_sign_spki(variant, FAKE_KEY).unwrap();
            let (alg, key) = decode_sign_spki(&der).unwrap();
            assert_eq!(alg, variant, "SPKI roundtrip failed for {variant:?}");
            assert_eq!(key, FAKE_KEY);
        }
    }
}
