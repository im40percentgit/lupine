//! Composite key and signature encoding for Lupine hybrid cryptographic types.
//!
//! Hybrid keys (X25519+ML-KEM, Ed25519+ML-DSA) combine a classical component
//! with a PQC component. This module serialises them as a length-prefixed
//! concatenation wrapped in a DER SEQUENCE:
//!
//! ```text
//! CompositeKey ::= SEQUENCE {
//!     classical  OCTET STRING,   -- X25519 or Ed25519 component
//!     pqc        OCTET STRING    -- ML-KEM or ML-DSA component
//! }
//! ```
//!
//! The outer SEQUENCE is identified by a Lupine-private OID (see `oid.rs`).
//! This format follows the spirit of draft-ietf-lamps-pq-composite-kem and
//! draft-ietf-lamps-pq-composite-sigs, which use a SEQUENCE OF individual keys.
//!
//! @decision DEC-SERIAL-005
//! @title Composite format: DER SEQUENCE vs simple length-prefix
//! @status accepted
//! @rationale IETF LAMPS composite drafts use `SEQUENCE { key1, key2 }` with
//!   individual DER-encoded components. We follow the same structure (two OCTET
//!   STRINGs in a SEQUENCE) for alignment with the drafts. A plain length-prefix
//!   (u32-BE + bytes + u32-BE + bytes) would be simpler but is not ASN.1-parseable
//!   by standard tools. The DER SEQUENCE costs ~6 bytes of overhead for the
//!   framing and is worth it for tooling compatibility. The outer OID wrapper
//!   uses a Lupine-private arc until IETF assigns final OIDs.

extern crate alloc;

use alloc::vec::Vec;

use der::{Decode, Encode, Sequence, asn1::OctetString};
use lupine_core::{Error, KemAlgorithm, Result, SerializationError, SignAlgorithm};

// OID constants are defined in crate::oid but variant discrimination in this
// module is handled by the TAG_* byte constants below, not by OID lookup.

// ---------------------------------------------------------------------------
// Variant tags — encode which parameter set is in use
// ---------------------------------------------------------------------------

/// Identifies the KEM parameter set for a composite key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositeKemVariant {
    /// X25519 + ML-KEM-512.
    X25519MlKem512,
    /// X25519 + ML-KEM-768.
    X25519MlKem768,
    /// X25519 + ML-KEM-1024.
    X25519MlKem1024,
}

/// Identifies the signature parameter set for a composite key/signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CompositeSignVariant {
    /// Ed25519 + ML-DSA-44.
    Ed25519MlDsa44,
    /// Ed25519 + ML-DSA-65.
    Ed25519MlDsa65,
    /// Ed25519 + ML-DSA-87.
    Ed25519MlDsa87,
}

impl CompositeKemVariant {
    /// The underlying ML-KEM parameter set.
    pub fn kem_algorithm(self) -> KemAlgorithm {
        match self {
            Self::X25519MlKem512 => KemAlgorithm::MlKem512,
            Self::X25519MlKem768 => KemAlgorithm::MlKem768,
            Self::X25519MlKem1024 => KemAlgorithm::MlKem1024,
        }
    }
}

impl CompositeSignVariant {
    /// The underlying ML-DSA parameter set.
    pub fn sign_algorithm(self) -> SignAlgorithm {
        match self {
            Self::Ed25519MlDsa44 => SignAlgorithm::MlDsa44,
            Self::Ed25519MlDsa65 => SignAlgorithm::MlDsa65,
            Self::Ed25519MlDsa87 => SignAlgorithm::MlDsa87,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal ASN.1 structure
// ---------------------------------------------------------------------------

/// Outer envelope: OID tag byte (1 byte, our private discriminant) + components.
///
/// We store the variant as a single-byte OCTET STRING before the component
/// pair. This lets decoders identify the parameter set without needing to
/// inspect key lengths.
///
/// Layout: `SEQUENCE { variant_oid OCTET STRING(1), classical OCTET STRING, pqc OCTET STRING }`
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct CompositeEnvelope {
    /// Single-byte tag identifying the composite variant (see TAG_* constants).
    pub variant_tag: OctetString,
    pub classical: OctetString,
    pub pqc: OctetString,
}

// Variant tag bytes embedded in the envelope.
const TAG_KEM_512: u8 = 0x01;
const TAG_KEM_768: u8 = 0x02;
const TAG_KEM_1024: u8 = 0x03;
const TAG_SIGN_44: u8 = 0x11;
const TAG_SIGN_65: u8 = 0x12;
const TAG_SIGN_87: u8 = 0x13;

// ---------------------------------------------------------------------------
// Composite KEM key encoding
// ---------------------------------------------------------------------------

/// Encode a composite KEM key (public or secret) to DER.
///
/// `classical_bytes` is the X25519 key component;
/// `pqc_bytes` is the ML-KEM component.
pub fn encode_composite_kem_key(
    variant: CompositeKemVariant,
    classical_bytes: &[u8],
    pqc_bytes: &[u8],
) -> Result<Vec<u8>> {
    let tag_byte = match variant {
        CompositeKemVariant::X25519MlKem512 => TAG_KEM_512,
        CompositeKemVariant::X25519MlKem768 => TAG_KEM_768,
        CompositeKemVariant::X25519MlKem1024 => TAG_KEM_1024,
    };
    encode_envelope(tag_byte, classical_bytes, pqc_bytes)
}

/// Decode a composite KEM key from DER.
///
/// Returns `(variant, classical_bytes, pqc_bytes)`.
pub fn decode_composite_kem_key(
    der_bytes: &[u8],
) -> Result<(CompositeKemVariant, Vec<u8>, Vec<u8>)> {
    let (tag, classical, pqc) = decode_envelope(der_bytes)?;
    let variant = match tag {
        TAG_KEM_512 => CompositeKemVariant::X25519MlKem512,
        TAG_KEM_768 => CompositeKemVariant::X25519MlKem768,
        TAG_KEM_1024 => CompositeKemVariant::X25519MlKem1024,
        _ => return Err(ser_err("unknown composite KEM variant tag")),
    };
    Ok((variant, classical, pqc))
}

// ---------------------------------------------------------------------------
// Composite signature key and signature encoding
// ---------------------------------------------------------------------------

/// Encode a composite signature key (signing or verifying) to DER.
///
/// `classical_bytes` is the Ed25519 key component;
/// `pqc_bytes` is the ML-DSA component.
pub fn encode_composite_sign_key(
    variant: CompositeSignVariant,
    classical_bytes: &[u8],
    pqc_bytes: &[u8],
) -> Result<Vec<u8>> {
    let tag_byte = match variant {
        CompositeSignVariant::Ed25519MlDsa44 => TAG_SIGN_44,
        CompositeSignVariant::Ed25519MlDsa65 => TAG_SIGN_65,
        CompositeSignVariant::Ed25519MlDsa87 => TAG_SIGN_87,
    };
    encode_envelope(tag_byte, classical_bytes, pqc_bytes)
}

/// Decode a composite signature key from DER.
pub fn decode_composite_sign_key(
    der_bytes: &[u8],
) -> Result<(CompositeSignVariant, Vec<u8>, Vec<u8>)> {
    let (tag, classical, pqc) = decode_envelope(der_bytes)?;
    let variant = match tag {
        TAG_SIGN_44 => CompositeSignVariant::Ed25519MlDsa44,
        TAG_SIGN_65 => CompositeSignVariant::Ed25519MlDsa65,
        TAG_SIGN_87 => CompositeSignVariant::Ed25519MlDsa87,
        _ => return Err(ser_err("unknown composite signature variant tag")),
    };
    Ok((variant, classical, pqc))
}

/// Encode a composite signature (two concatenated signatures) to DER.
///
/// `classical_sig` is the Ed25519 signature;
/// `pqc_sig` is the ML-DSA signature.
pub fn encode_composite_signature(
    variant: CompositeSignVariant,
    classical_sig: &[u8],
    pqc_sig: &[u8],
) -> Result<Vec<u8>> {
    encode_composite_sign_key(variant, classical_sig, pqc_sig)
}

/// Decode a composite signature from DER.
///
/// Returns `(variant, classical_sig, pqc_sig)`.
pub fn decode_composite_signature(
    der_bytes: &[u8],
) -> Result<(CompositeSignVariant, Vec<u8>, Vec<u8>)> {
    decode_composite_sign_key(der_bytes)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn encode_envelope(tag_byte: u8, classical: &[u8], pqc: &[u8]) -> Result<Vec<u8>> {
    // OctetString::new (alloc feature) takes impl Into<Box<[u8]>>; Vec<u8>
    // satisfies that bound. The single-byte tag is collected into a Vec first.
    let env = CompositeEnvelope {
        variant_tag: OctetString::new(vec![tag_byte])
            .map_err(|_| ser_err("variant tag encoding failed"))?,
        classical: OctetString::new(classical.to_vec())
            .map_err(|_| ser_err("classical component too large for DER"))?,
        pqc: OctetString::new(pqc.to_vec())
            .map_err(|_| ser_err("PQC component too large for DER"))?,
    };
    env.to_der().map_err(|_| ser_err("composite DER encoding failed"))
}

fn decode_envelope(der_bytes: &[u8]) -> Result<(u8, Vec<u8>, Vec<u8>)> {
    let env = CompositeEnvelope::from_der(der_bytes)
        .map_err(|_| ser_err("invalid composite DER"))?;
    let tag_slice = env.variant_tag.as_bytes();
    if tag_slice.len() != 1 {
        return Err(ser_err("composite variant tag must be exactly 1 byte"));
    }
    Ok((
        tag_slice[0],
        env.classical.as_bytes().to_vec(),
        env.pqc.as_bytes().to_vec(),
    ))
}

fn ser_err(message: &'static str) -> Error {
    Error::Serialization(SerializationError { message })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const CLASSICAL: &[u8] = b"classical_key_32bytes_x25519_ed25519";
    const PQC: &[u8] = b"pqc_key_bytes_ml_kem_or_ml_dsa_component";

    // --- Composite KEM ---

    #[test]
    fn composite_kem_512_roundtrip() {
        let der = encode_composite_kem_key(CompositeKemVariant::X25519MlKem512, CLASSICAL, PQC).unwrap();
        let (v, c, p) = decode_composite_kem_key(&der).unwrap();
        assert_eq!(v, CompositeKemVariant::X25519MlKem512);
        assert_eq!(c, CLASSICAL);
        assert_eq!(p, PQC);
    }

    #[test]
    fn composite_kem_768_roundtrip() {
        let der = encode_composite_kem_key(CompositeKemVariant::X25519MlKem768, CLASSICAL, PQC).unwrap();
        let (v, c, p) = decode_composite_kem_key(&der).unwrap();
        assert_eq!(v, CompositeKemVariant::X25519MlKem768);
        assert_eq!(c, CLASSICAL);
        assert_eq!(p, PQC);
    }

    #[test]
    fn composite_kem_1024_roundtrip() {
        let der = encode_composite_kem_key(CompositeKemVariant::X25519MlKem1024, CLASSICAL, PQC).unwrap();
        let (v, c, p) = decode_composite_kem_key(&der).unwrap();
        assert_eq!(v, CompositeKemVariant::X25519MlKem1024);
        assert_eq!(c, CLASSICAL);
        assert_eq!(p, PQC);
    }

    // --- Composite signature keys ---

    #[test]
    fn composite_sign_key_44_roundtrip() {
        let der = encode_composite_sign_key(CompositeSignVariant::Ed25519MlDsa44, CLASSICAL, PQC).unwrap();
        let (v, c, p) = decode_composite_sign_key(&der).unwrap();
        assert_eq!(v, CompositeSignVariant::Ed25519MlDsa44);
        assert_eq!(c, CLASSICAL);
        assert_eq!(p, PQC);
    }

    #[test]
    fn composite_sign_key_65_roundtrip() {
        let der = encode_composite_sign_key(CompositeSignVariant::Ed25519MlDsa65, CLASSICAL, PQC).unwrap();
        let (v, c, p) = decode_composite_sign_key(&der).unwrap();
        assert_eq!(v, CompositeSignVariant::Ed25519MlDsa65);
        assert_eq!(c, CLASSICAL);
        assert_eq!(p, PQC);
    }

    #[test]
    fn composite_sign_key_87_roundtrip() {
        let der = encode_composite_sign_key(CompositeSignVariant::Ed25519MlDsa87, CLASSICAL, PQC).unwrap();
        let (v, c, p) = decode_composite_sign_key(&der).unwrap();
        assert_eq!(v, CompositeSignVariant::Ed25519MlDsa87);
        assert_eq!(c, CLASSICAL);
        assert_eq!(p, PQC);
    }

    // --- Composite signatures ---

    #[test]
    fn composite_signature_roundtrip() {
        let sig_classical = b"ed25519_sig_64_bytes_placeholder_xx";
        let sig_pqc = b"ml_dsa_sig_bytes_placeholder";
        let der = encode_composite_signature(
            CompositeSignVariant::Ed25519MlDsa65,
            sig_classical,
            sig_pqc,
        ).unwrap();
        let (v, c, p) = decode_composite_signature(&der).unwrap();
        assert_eq!(v, CompositeSignVariant::Ed25519MlDsa65);
        assert_eq!(c, sig_classical);
        assert_eq!(p, sig_pqc);
    }

    // --- Variant isolation ---

    #[test]
    fn variant_tags_are_distinct() {
        let der512 = encode_composite_kem_key(CompositeKemVariant::X25519MlKem512, CLASSICAL, PQC).unwrap();
        let der768 = encode_composite_kem_key(CompositeKemVariant::X25519MlKem768, CLASSICAL, PQC).unwrap();
        // Different variants produce different bytes
        assert_ne!(der512, der768);
        // And decode to the correct variant
        let (v512, _, _) = decode_composite_kem_key(&der512).unwrap();
        let (v768, _, _) = decode_composite_kem_key(&der768).unwrap();
        assert_eq!(v512, CompositeKemVariant::X25519MlKem512);
        assert_eq!(v768, CompositeKemVariant::X25519MlKem768);
    }

    #[test]
    fn kem_tag_rejected_as_sign() {
        // A composite KEM blob must not decode as a composite sign key.
        let der = encode_composite_kem_key(CompositeKemVariant::X25519MlKem512, CLASSICAL, PQC).unwrap();
        assert!(decode_composite_sign_key(&der).is_err());
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_composite_kem_key(b"garbage").is_err());
        assert!(decode_composite_sign_key(b"\x00\x01\x02").is_err());
    }

    #[test]
    fn empty_components_roundtrip() {
        let der = encode_composite_kem_key(CompositeKemVariant::X25519MlKem512, &[], &[]).unwrap();
        let (v, c, p) = decode_composite_kem_key(&der).unwrap();
        assert_eq!(v, CompositeKemVariant::X25519MlKem512);
        assert_eq!(c, b"");
        assert_eq!(p, b"");
    }

    #[test]
    fn variant_algorithm_accessors() {
        assert_eq!(CompositeKemVariant::X25519MlKem768.kem_algorithm(), KemAlgorithm::MlKem768);
        assert_eq!(CompositeSignVariant::Ed25519MlDsa87.sign_algorithm(), SignAlgorithm::MlDsa87);
    }
}
