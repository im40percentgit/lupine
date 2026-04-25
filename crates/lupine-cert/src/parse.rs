//! Certificate parsing from DER and PEM formats.
//!
//! Provides a user-facing [`Certificate`] type that wraps the raw ASN.1
//! structures from [`crate::asn1`] with a convenient accessor API.
//!
//! # Example
//!
//! ```rust,ignore
//! use lupine_cert::parse::Certificate;
//!
//! let cert = Certificate::from_pem(&pem_string)?;
//! println!("Subject: {:?}", cert.subject_cn());
//! println!("Issuer: {:?}", cert.issuer_cn());
//! ```
//!
//! @decision DEC-CERT-003
//! @title Eagerly cache decoded CN strings for zero-copy accessor API
//! @status accepted
//! @rationale `subject_cn()` and `issuer_cn()` return `Option<&str>`, but the
//!   underlying `decode_cn()` produces an owned `String`. To avoid allocation
//!   on every call and lifetime gymnastics, we decode and cache the CN values
//!   at parse time inside the `Certificate` struct. The memory overhead is
//!   negligible (two short strings per certificate) and the API is cleaner.

use der::asn1::ObjectIdentifier;
use lupine_core::{Error, Result, SerializationError};
use lupine_serial::pem;

use crate::asn1::{self, X509Certificate};

// ---------------------------------------------------------------------------
// Certificate — user-facing parsed certificate
// ---------------------------------------------------------------------------

/// A parsed X.509v3 certificate with convenient accessors.
///
/// Stores the original DER bytes alongside parsed ASN.1 fields. The raw TBS
/// (to-be-signed) bytes are preserved exactly as they appeared in the input,
/// ensuring signature verification uses the original encoding rather than a
/// re-encoding. Decoded CN values are cached at parse time for zero-copy
/// access via [`subject_cn()`](Self::subject_cn) and
/// [`issuer_cn()`](Self::issuer_cn).
#[derive(Clone, Debug)]
pub struct Certificate {
    /// Full DER-encoded certificate.
    der: Vec<u8>,
    /// Raw DER bytes of just the TBSCertificate (for signature verification).
    tbs_der: Vec<u8>,
    /// Parsed ASN.1 certificate structure.
    parsed: X509Certificate,
    /// Cached subject CN (decoded and prefix-stripped at parse time).
    subject_cn_cache: Option<String>,
    /// Cached issuer CN (decoded and prefix-stripped at parse time).
    issuer_cn_cache: Option<String>,
}

impl Certificate {
    /// Parse a certificate from DER bytes.
    ///
    /// Extracts the raw TBS bytes from the outer SEQUENCE for signature
    /// verification, then parses the full certificate structure.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if the DER is malformed or does not
    /// contain a valid X.509 certificate.
    pub fn from_der(bytes: &[u8]) -> Result<Self> {
        // Parse the outer SEQUENCE to extract raw TBS bytes.
        let (_tag, body) = asn1::parse_tlv(bytes)?;
        let tbs_total_len = asn1::tlv_total_len(body)?;
        let tbs_der = body[..tbs_total_len].to_vec();

        // Parse the full certificate.
        let parsed = X509Certificate::from_der(bytes)?;

        // Cache decoded CN values.
        let subject_cn_cache = extract_cn(&parsed.tbs_certificate.subject);
        let issuer_cn_cache = extract_cn(&parsed.tbs_certificate.issuer);

        Ok(Self {
            der: bytes.to_vec(),
            tbs_der,
            parsed,
            subject_cn_cache,
            issuer_cn_cache,
        })
    }

    /// Parse a certificate from a PEM-encoded string.
    ///
    /// Expects the PEM label `"CERTIFICATE"` (standard X.509 convention).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Serialization`] if the PEM is malformed, the label is
    /// wrong, or the inner DER is not a valid X.509 certificate.
    pub fn from_pem(pem_str: &str) -> Result<Self> {
        let (label, der_bytes) = pem::decode_pem(pem_str)?;
        if label != "CERTIFICATE" {
            return Err(ser_err("expected CERTIFICATE PEM label"));
        }
        Self::from_der(&der_bytes)
    }

    /// Subject common name (CN), if present.
    ///
    /// Returns the bare CN value (e.g. `"my-server"`) without the `"CN="`
    /// prefix that the certificate's Distinguished Name encoding includes.
    pub fn subject_cn(&self) -> Option<&str> {
        self.subject_cn_cache.as_deref()
    }

    /// Issuer common name (CN), if present.
    ///
    /// See [`subject_cn()`](Self::subject_cn) for details on prefix stripping.
    pub fn issuer_cn(&self) -> Option<&str> {
        self.issuer_cn_cache.as_deref()
    }

    /// The OID of the signature algorithm used to sign this certificate.
    pub fn signature_algorithm_oid(&self) -> &ObjectIdentifier {
        &self.parsed.signature_algorithm.algorithm
    }

    /// Raw DER bytes of the TBSCertificate (the data that was signed).
    ///
    /// These are the original bytes from the input, not a re-encoding,
    /// ensuring correct signature verification.
    pub fn tbs_bytes(&self) -> &[u8] {
        &self.tbs_der
    }

    /// Raw signature bytes (the BIT STRING content, without the unused-bits
    /// prefix byte).
    pub fn signature_bytes(&self) -> &[u8] {
        self.parsed.signature_value.as_bytes().unwrap_or_default()
    }

    /// Raw subject public key bytes (the BIT STRING content from
    /// SubjectPublicKeyInfo).
    pub fn public_key_bytes(&self) -> &[u8] {
        self.parsed
            .tbs_certificate
            .subject_public_key_info
            .subject_public_key
            .as_bytes()
            .unwrap_or_default()
    }

    /// The OID of the subject's public key algorithm.
    pub fn public_key_algorithm_oid(&self) -> &ObjectIdentifier {
        &self
            .parsed
            .tbs_certificate
            .subject_public_key_info
            .algorithm
            .algorithm
    }

    /// Full DER-encoded certificate bytes.
    pub fn der_bytes(&self) -> &[u8] {
        &self.der
    }

    /// PEM-encode this certificate with the `"CERTIFICATE"` label.
    pub fn to_pem(&self) -> String {
        // encode_pem only fails on invalid labels, and "CERTIFICATE" is valid.
        pem::encode_pem("CERTIFICATE", &self.der).expect("CERTIFICATE is a valid PEM label")
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract CN from raw DER name bytes, stripping the "CN=" prefix that
/// [`crate::asn1::encode_cn`] stores in the UTF8String value.
fn extract_cn(name_der: &[u8]) -> Option<String> {
    let raw = asn1::decode_cn(name_der)?;
    if let Some(stripped) = raw.strip_prefix("CN=") {
        Some(stripped.to_string())
    } else {
        Some(raw)
    }
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
    use crate::generate::{CertAlgorithm, CertBuilder};

    /// Run `f` on a thread with a 32 MB stack (ML-DSA needs large stacks
    /// in debug builds).
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn parse_self_signed() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=parse-test")
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert_eq!(cert.subject_cn(), Some("parse-test"));
            assert_eq!(cert.issuer_cn(), Some("parse-test"));
            assert!(!cert.tbs_bytes().is_empty());
            assert!(!cert.signature_bytes().is_empty());
            assert!(!cert.public_key_bytes().is_empty());
        });
    }

    #[test]
    fn parse_pem_round_trip() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=pem-test")
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            let pem_str = gen.pem.clone();
            let cert = Certificate::from_pem(&pem_str).unwrap();
            assert_eq!(cert.subject_cn(), Some("pem-test"));
            assert_eq!(cert.to_pem(), pem_str);
        });
    }

    #[test]
    fn parse_ca_signed_leaf() {
        with_large_stack(|| {
            let ca = CertBuilder::new()
                .subject("CN=Test CA")
                .ca(true)
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            let leaf = CertBuilder::new()
                .subject("CN=leaf")
                .signed_by(&ca, CertAlgorithm::MlDsa65)
                .unwrap();

            let cert = Certificate::from_der(&leaf.der_bytes).unwrap();
            assert_eq!(cert.subject_cn(), Some("leaf"));
            assert_eq!(cert.issuer_cn(), Some("Test CA"));
        });
    }

    #[test]
    fn signature_algorithm_oid_matches() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=oid-test")
                .self_signed(CertAlgorithm::MlDsa44)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert_eq!(
                *cert.signature_algorithm_oid(),
                lupine_serial::oid::OID_ML_DSA_44
            );
        });
    }

    #[test]
    fn der_bytes_roundtrip() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=der-test")
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert_eq!(cert.der_bytes(), gen.der_bytes.as_slice());
        });
    }

    #[test]
    fn invalid_der_rejected() {
        assert!(Certificate::from_der(b"not a certificate").is_err());
        assert!(Certificate::from_der(&[]).is_err());
    }

    #[test]
    fn invalid_pem_rejected() {
        assert!(Certificate::from_pem("not pem").is_err());
        // Wrong label
        let wrong_label = lupine_serial::pem::encode_pem("PUBLIC KEY", b"\x30\x00").unwrap();
        assert!(Certificate::from_pem(&wrong_label).is_err());
    }
}
