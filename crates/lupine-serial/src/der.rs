//! DER encoding and decoding for Lupine PQC key types.
//!
//! Keys are serialized as `OneAsymmetricKey`-style DER structures:
//!
//! ```text
//! KeyInfo ::= SEQUENCE {
//!     algorithm   AlgorithmIdentifier,
//!     keyData     OCTET STRING
//! }
//!
//! AlgorithmIdentifier ::= SEQUENCE {
//!     algorithm   OBJECT IDENTIFIER,
//!     parameters  NULL OPTIONAL
//! }
//! ```
//!
//! This matches the PKCS #8 / RFC 5958 spirit without pulling in the `pkcs8`
//! crate (which has its own RC dependency chain). Public keys use the same
//! structure; the caller selects the appropriate label ("PUBLIC KEY" vs
//! "PRIVATE KEY") when encoding to PEM.
//!
//! @decision DEC-SERIAL-002
//! @title DER structure: minimal KeyInfo vs full PKCS8/OneAsymmetricKey
//! @status accepted
//! @rationale Full PKCS8 (`OneAsymmetricKey`) includes a version field and
//!   optional public key field. For PQC keys, the public key can always be
//!   recomputed from the secret key (or is separate), and the version overhead
//!   is pure noise. A minimal `SEQUENCE { AlgorithmIdentifier, OCTET STRING }`
//!   is interoperable with any DER parser that understands the OID, avoids
//!   pulling `pkcs8` (which has RC deps), and keeps the serialisation layer
//!   thin as specified. Full PKCS8 support can be layered on later.

extern crate alloc;

use alloc::vec::Vec;

use der::{
    asn1::{ObjectIdentifier, OctetString},
    Decode, Encode, Sequence,
};
use lupine_core::{Error, KemAlgorithm, Result, SerializationError, SignAlgorithm};

use crate::oid::{kem_from_oid, oid_for_kem, oid_for_sign, sign_from_oid};

// ---------------------------------------------------------------------------
// Internal ASN.1 structures
// ---------------------------------------------------------------------------

/// `AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters NULL OPTIONAL }`
///
/// We use `Option<()>` for parameters — `()` encodes as ASN.1 NULL, matching
/// the convention for PQC algorithm identifiers that carry no parameters.
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct AlgorithmIdentifier {
    pub algorithm: ObjectIdentifier,
    pub parameters: Option<()>,
}

/// `KeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, keyData OCTET STRING }`
///
/// Wraps raw key bytes with their algorithm identifier.  Used for both public
/// and secret keys (the PEM label distinguishes the two).
#[derive(Clone, Debug, Eq, PartialEq, Sequence)]
struct KeyInfo {
    pub algorithm: AlgorithmIdentifier,
    pub key_data: OctetString,
}

// ---------------------------------------------------------------------------
// KEM key encoding
// ---------------------------------------------------------------------------

/// Encode a KEM public key to DER.
///
/// The output is a `SEQUENCE { AlgorithmIdentifier, OCTET STRING }` with the
/// NIST-assigned OID for the given algorithm.
pub fn encode_kem_public_key_der(alg: KemAlgorithm, key_bytes: &[u8]) -> Result<Vec<u8>> {
    let info = KeyInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: oid_for_kem(alg),
            parameters: None,
        },
        key_data: OctetString::new(key_bytes.to_vec())
            .map_err(|_| ser_err("key too large for DER"))?,
    };
    info.to_der().map_err(|_| ser_err("DER encoding failed"))
}

/// Decode a KEM public key from DER.
///
/// Returns the `(algorithm, raw_key_bytes)` pair. The caller is responsible
/// for interpreting the bytes as the correct concrete type.
pub fn decode_kem_public_key_der(der_bytes: &[u8]) -> Result<(KemAlgorithm, Vec<u8>)> {
    let info =
        KeyInfo::from_der(der_bytes).map_err(|_| ser_err("invalid DER for KEM public key"))?;
    let alg = kem_from_oid(&info.algorithm.algorithm).ok_or_else(|| ser_err("unknown KEM OID"))?;
    Ok((alg, info.key_data.as_bytes().to_vec()))
}

/// Encode a KEM secret key to DER.
pub fn encode_kem_secret_key_der(alg: KemAlgorithm, key_bytes: &[u8]) -> Result<Vec<u8>> {
    encode_kem_public_key_der(alg, key_bytes)
}

/// Decode a KEM secret key from DER.
///
/// The DER structure is identical to the public key format; the PEM label
/// carries the "PUBLIC KEY" vs "PRIVATE KEY" distinction.
pub fn decode_kem_secret_key_der(der_bytes: &[u8]) -> Result<(KemAlgorithm, Vec<u8>)> {
    decode_kem_public_key_der(der_bytes)
}

// ---------------------------------------------------------------------------
// Signature key and signature encoding
// ---------------------------------------------------------------------------

/// Encode a signature verifying key (public key) to DER.
pub fn encode_sign_public_key_der(alg: SignAlgorithm, key_bytes: &[u8]) -> Result<Vec<u8>> {
    let info = KeyInfo {
        algorithm: AlgorithmIdentifier {
            algorithm: oid_for_sign(alg),
            parameters: None,
        },
        key_data: OctetString::new(key_bytes.to_vec())
            .map_err(|_| ser_err("key too large for DER"))?,
    };
    info.to_der().map_err(|_| ser_err("DER encoding failed"))
}

/// Decode a signature verifying key from DER.
pub fn decode_sign_public_key_der(der_bytes: &[u8]) -> Result<(SignAlgorithm, Vec<u8>)> {
    let info =
        KeyInfo::from_der(der_bytes).map_err(|_| ser_err("invalid DER for sign public key"))?;
    let alg =
        sign_from_oid(&info.algorithm.algorithm).ok_or_else(|| ser_err("unknown signature OID"))?;
    Ok((alg, info.key_data.as_bytes().to_vec()))
}

/// Encode a signature signing key (secret key) to DER.
pub fn encode_sign_secret_key_der(alg: SignAlgorithm, key_bytes: &[u8]) -> Result<Vec<u8>> {
    encode_sign_public_key_der(alg, key_bytes)
}

/// Decode a signature signing key from DER.
pub fn decode_sign_secret_key_der(der_bytes: &[u8]) -> Result<(SignAlgorithm, Vec<u8>)> {
    decode_sign_public_key_der(der_bytes)
}

/// Encode a detached signature blob to DER.
///
/// The signature is wrapped in the same `KeyInfo` structure as keys, using
/// the algorithm OID to identify which scheme produced it.
pub fn encode_signature_der(alg: SignAlgorithm, sig_bytes: &[u8]) -> Result<Vec<u8>> {
    encode_sign_public_key_der(alg, sig_bytes)
}

/// Decode a detached signature blob from DER.
pub fn decode_signature_der(der_bytes: &[u8]) -> Result<(SignAlgorithm, Vec<u8>)> {
    decode_sign_public_key_der(der_bytes)
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

    // Small synthetic key bytes — real key sizes are large; these are just
    // byte vectors to test the DER framing, not cryptographic correctness.
    const FAKE_KEY: &[u8] = b"fake_key_bytes_for_der_framing_test";

    #[test]
    fn kem_public_key_roundtrip_512() {
        let der = encode_kem_public_key_der(KemAlgorithm::MlKem512, FAKE_KEY).unwrap();
        let (alg, key) = decode_kem_public_key_der(&der).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem512);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn kem_public_key_roundtrip_768() {
        let der = encode_kem_public_key_der(KemAlgorithm::MlKem768, FAKE_KEY).unwrap();
        let (alg, key) = decode_kem_public_key_der(&der).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem768);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn kem_public_key_roundtrip_1024() {
        let der = encode_kem_public_key_der(KemAlgorithm::MlKem1024, FAKE_KEY).unwrap();
        let (alg, key) = decode_kem_public_key_der(&der).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem1024);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn kem_secret_key_roundtrip() {
        let der = encode_kem_secret_key_der(KemAlgorithm::MlKem768, FAKE_KEY).unwrap();
        let (alg, key) = decode_kem_secret_key_der(&der).unwrap();
        assert_eq!(alg, KemAlgorithm::MlKem768);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_public_key_roundtrip_ml_dsa_44() {
        let der = encode_sign_public_key_der(SignAlgorithm::MlDsa44, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_public_key_der(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa44);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_public_key_roundtrip_ml_dsa_65() {
        let der = encode_sign_public_key_der(SignAlgorithm::MlDsa65, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_public_key_der(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa65);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_public_key_roundtrip_ml_dsa_87() {
        let der = encode_sign_public_key_der(SignAlgorithm::MlDsa87, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_public_key_der(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa87);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_public_key_roundtrip_slh_dsa_sha2_128s() {
        let der = encode_sign_public_key_der(SignAlgorithm::SlhDsaSha2128s, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_public_key_der(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::SlhDsaSha2128s);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_public_key_roundtrip_slh_dsa_shake_256f() {
        let der = encode_sign_public_key_der(SignAlgorithm::SlhDsaShake256f, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_public_key_der(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::SlhDsaShake256f);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn sign_secret_key_roundtrip() {
        let der = encode_sign_secret_key_der(SignAlgorithm::MlDsa87, FAKE_KEY).unwrap();
        let (alg, key) = decode_sign_secret_key_der(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa87);
        assert_eq!(key, FAKE_KEY);
    }

    #[test]
    fn signature_roundtrip() {
        let der = encode_signature_der(SignAlgorithm::MlDsa44, FAKE_KEY).unwrap();
        let (alg, sig) = decode_signature_der(&der).unwrap();
        assert_eq!(alg, SignAlgorithm::MlDsa44);
        assert_eq!(sig, FAKE_KEY);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_kem_public_key_der(b"not der").is_err());
        assert!(decode_sign_public_key_der(b"\x00\x00\x00").is_err());
    }

    #[test]
    fn der_bytes_are_not_empty() {
        // Sanity: DER output must be longer than the raw key bytes alone.
        let der = encode_kem_public_key_der(KemAlgorithm::MlKem512, FAKE_KEY).unwrap();
        assert!(der.len() > FAKE_KEY.len());
    }

    #[test]
    fn all_slh_dsa_variants_roundtrip() {
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
            let der = encode_sign_public_key_der(variant, FAKE_KEY).unwrap();
            let (alg, key) = decode_sign_public_key_der(&der).unwrap();
            assert_eq!(alg, variant, "roundtrip failed for {variant:?}");
            assert_eq!(key, FAKE_KEY);
        }
    }
}
