//! PEM encoding and decoding for Lupine PQC key types.
//!
//! Wraps DER-encoded bytes in RFC 7468 PEM format using the `pem-rfc7468`
//! crate. The caller supplies the label (e.g. `"PUBLIC KEY"`, `"PRIVATE KEY"`,
//! `"SIGNATURE"`), which becomes the PEM header/footer:
//!
//! ```text
//! -----BEGIN PUBLIC KEY-----
//! <base64-encoded DER>
//! -----END PUBLIC KEY-----
//! ```
//!
//! Standard labels for PQC keys follow the same conventions as classical keys:
//! - `"PUBLIC KEY"` — SubjectPublicKeyInfo / verifying keys
//! - `"PRIVATE KEY"` — OneAsymmetricKey / signing/decapsulation keys
//! - `"SIGNATURE"` — detached signature blobs (Lupine convention)
//!
//! @decision DEC-SERIAL-003
//! @title PEM label conventions for PQC keys
//! @status accepted
//! @rationale Using the standard `"PUBLIC KEY"` and `"PRIVATE KEY"` labels
//!   (from PKCS#8 / RFC 5958) means existing tooling (openssl, ssh-keygen
//!   PEM parsers, etc.) will parse the envelope without modifications, even
//!   if they cannot interpret the PQC OID inside. The non-standard
//!   `"SIGNATURE"` label is a Lupine convention for detached signatures;
//!   no RFC defines a PEM label for raw signatures, so we pick a descriptive
//!   name. This is clearly documented so consumers know it is non-standard.

extern crate alloc;

use alloc::string::String;

use lupine_core::{Error, Result, SerializationError};
use pem_rfc7468::LineEnding;

// ---------------------------------------------------------------------------
// PEM label constants
// ---------------------------------------------------------------------------

/// Standard PEM label for public keys (verifying keys, KEM encapsulation keys).
pub const LABEL_PUBLIC_KEY: &str = "PUBLIC KEY";

/// Standard PEM label for private keys (signing keys, KEM decapsulation keys).
pub const LABEL_PRIVATE_KEY: &str = "PRIVATE KEY";

/// Lupine convention label for detached signature blobs.
pub const LABEL_SIGNATURE: &str = "SIGNATURE";

// ---------------------------------------------------------------------------
// Core encode / decode
// ---------------------------------------------------------------------------

/// Encode DER bytes to PEM with the given label.
///
/// Uses Unix line endings (LF) by default, which is the most portable choice
/// for machine-generated PEM. The output always ends with a newline.
///
/// # Errors
/// Returns [`Error::Serialization`] if `label` is not a valid RFC 7468 PEM
/// label or if the base64 encoding fails (which should not happen in practice).
pub fn encode_pem(label: &str, der_bytes: &[u8]) -> Result<String> {
    pem_rfc7468::encode_string(label, LineEnding::LF, der_bytes)
        .map_err(|_| ser_err("PEM encoding failed"))
}

/// Decode a PEM document, returning `(label, der_bytes)`.
///
/// The label is returned as an owned `String` so the caller can verify it
/// matches the expected key type before decoding the DER payload.
///
/// # Errors
/// Returns [`Error::Serialization`] if the input is not valid RFC 7468 PEM.
pub fn decode_pem(pem_str: &str) -> Result<(String, alloc::vec::Vec<u8>)> {
    let (label, doc) =
        pem_rfc7468::decode_vec(pem_str.as_bytes()).map_err(|_| ser_err("PEM decoding failed"))?;
    Ok((label.to_owned(), doc))
}

// ---------------------------------------------------------------------------
// Convenience wrappers that encode DER + wrap in PEM in one step
// ---------------------------------------------------------------------------

/// Encode a public key's DER bytes as a `"PUBLIC KEY"` PEM block.
pub fn encode_public_key_pem(der_bytes: &[u8]) -> Result<String> {
    encode_pem(LABEL_PUBLIC_KEY, der_bytes)
}

/// Encode a private key's DER bytes as a `"PRIVATE KEY"` PEM block.
pub fn encode_private_key_pem(der_bytes: &[u8]) -> Result<String> {
    encode_pem(LABEL_PRIVATE_KEY, der_bytes)
}

/// Encode a signature's DER bytes as a `"SIGNATURE"` PEM block.
pub fn encode_signature_pem(der_bytes: &[u8]) -> Result<String> {
    encode_pem(LABEL_SIGNATURE, der_bytes)
}

/// Decode a `"PUBLIC KEY"` PEM block, returning the inner DER bytes.
///
/// # Errors
/// Returns an error if the PEM is malformed or if the label is not
/// `"PUBLIC KEY"`.
pub fn decode_public_key_pem(pem_str: &str) -> Result<alloc::vec::Vec<u8>> {
    let (label, der) = decode_pem(pem_str)?;
    if label != LABEL_PUBLIC_KEY {
        return Err(ser_err("expected PUBLIC KEY PEM label"));
    }
    Ok(der)
}

/// Decode a `"PRIVATE KEY"` PEM block, returning the inner DER bytes.
pub fn decode_private_key_pem(pem_str: &str) -> Result<alloc::vec::Vec<u8>> {
    let (label, der) = decode_pem(pem_str)?;
    if label != LABEL_PRIVATE_KEY {
        return Err(ser_err("expected PRIVATE KEY PEM label"));
    }
    Ok(der)
}

/// Decode a `"SIGNATURE"` PEM block, returning the inner DER bytes.
pub fn decode_signature_pem(pem_str: &str) -> Result<alloc::vec::Vec<u8>> {
    let (label, der) = decode_pem(pem_str)?;
    if label != LABEL_SIGNATURE {
        return Err(ser_err("expected SIGNATURE PEM label"));
    }
    Ok(der)
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

    const FAKE_DER: &[u8] = b"\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02";

    #[test]
    fn encode_decode_roundtrip_public_key() {
        let pem = encode_public_key_pem(FAKE_DER).unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        assert!(pem.contains("-----END PUBLIC KEY-----"));
        let der = decode_public_key_pem(&pem).unwrap();
        assert_eq!(der, FAKE_DER);
    }

    #[test]
    fn encode_decode_roundtrip_private_key() {
        let pem = encode_private_key_pem(FAKE_DER).unwrap();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        let der = decode_private_key_pem(&pem).unwrap();
        assert_eq!(der, FAKE_DER);
    }

    #[test]
    fn encode_decode_roundtrip_signature() {
        let pem = encode_signature_pem(FAKE_DER).unwrap();
        assert!(pem.starts_with("-----BEGIN SIGNATURE-----"));
        let der = decode_signature_pem(&pem).unwrap();
        assert_eq!(der, FAKE_DER);
    }

    #[test]
    fn wrong_label_rejected() {
        let pem = encode_private_key_pem(FAKE_DER).unwrap();
        assert!(decode_public_key_pem(&pem).is_err());
    }

    #[test]
    fn custom_label_roundtrip() {
        let pem = encode_pem("CERTIFICATE", FAKE_DER).unwrap();
        let (label, der) = decode_pem(&pem).unwrap();
        assert_eq!(label, "CERTIFICATE");
        assert_eq!(der, FAKE_DER);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(decode_pem("not pem at all").is_err());
    }

    #[test]
    fn small_payload_roundtrip() {
        // RFC 7468 requires non-empty base64 content; use a minimal 1-byte payload.
        let der = decode_public_key_pem(&encode_public_key_pem(&[0xffu8]).unwrap()).unwrap();
        assert_eq!(der, [0xff]);
    }

    #[test]
    fn pem_output_ends_with_newline() {
        let pem = encode_public_key_pem(FAKE_DER).unwrap();
        assert!(pem.ends_with('\n'));
    }
}
