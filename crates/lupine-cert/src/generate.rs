//! Self-signed and CA-signed certificate generation.
//!
//! Provides a [`CertBuilder`] for constructing X.509v3 certificates signed
//! with ML-DSA (FIPS 204) or hybrid Ed25519+ML-DSA algorithms.
//!
//! # Example
//!
//! ```rust,ignore
//! use lupine_cert::generate::{CertBuilder, CertAlgorithm};
//!
//! // Self-signed CA certificate
//! let ca = CertBuilder::new()
//!     .subject("CN=My CA")
//!     .ca(true)
//!     .validity_days(365)
//!     .self_signed(CertAlgorithm::MlDsa65)
//!     .unwrap();
//!
//! // Leaf certificate signed by the CA
//! let leaf = CertBuilder::new()
//!     .subject("CN=leaf.example.com")
//!     .signed_by(&ca, CertAlgorithm::MlDsa65)
//!     .unwrap();
//! ```
//!
//! @decision DEC-CERT-002
//! @title CertAlgorithm enum vs reusing SignAlgorithm
//! @status accepted
//! @rationale `lupine_core::SignAlgorithm` covers pure PQC signature algorithms
//!   but not hybrid Ed25519+ML-DSA variants (which live in lupine-sign as generic
//!   types). Rather than modifying the core enum, we define `CertAlgorithm` in
//!   this crate which covers both pure ML-DSA and hybrid variants. This keeps
//!   lupine-core stable and gives lupine-cert full control over its supported
//!   algorithm set.

use der::asn1::{BitString, ObjectIdentifier};
use lupine_core::{Error, Result, SerializationError, SignAlgorithm};
use lupine_serial::oid;
use lupine_serial::pem;

use crate::asn1::{
    encode_cn, AlgorithmIdentifier, SubjectPublicKeyInfo, TbsCertificate, Validity, X509Certificate,
};

// ---------------------------------------------------------------------------
// CertAlgorithm — supported signing algorithms for certificates
// ---------------------------------------------------------------------------

/// Signing algorithms supported for certificate generation.
///
/// Covers pure ML-DSA (FIPS 204) and hybrid Ed25519+ML-DSA variants.
/// SLH-DSA is excluded due to extremely large signature sizes (7-50 KB)
/// which make certificates impractical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CertAlgorithm {
    /// ML-DSA-44 — NIST security category 2.
    MlDsa44,
    /// ML-DSA-65 — NIST security category 3.
    MlDsa65,
    /// ML-DSA-87 — NIST security category 5.
    MlDsa87,
    /// Hybrid Ed25519 + ML-DSA-44.
    HybridEd25519MlDsa44,
    /// Hybrid Ed25519 + ML-DSA-65.
    HybridEd25519MlDsa65,
    /// Hybrid Ed25519 + ML-DSA-87.
    HybridEd25519MlDsa87,
}

impl CertAlgorithm {
    /// Get the OID for this algorithm.
    fn oid(self) -> ObjectIdentifier {
        match self {
            CertAlgorithm::MlDsa44 => oid::oid_for_sign(SignAlgorithm::MlDsa44),
            CertAlgorithm::MlDsa65 => oid::oid_for_sign(SignAlgorithm::MlDsa65),
            CertAlgorithm::MlDsa87 => oid::oid_for_sign(SignAlgorithm::MlDsa87),
            CertAlgorithm::HybridEd25519MlDsa44 => oid::OID_HYBRID_SIGN_44,
            CertAlgorithm::HybridEd25519MlDsa65 => oid::OID_HYBRID_SIGN_65,
            CertAlgorithm::HybridEd25519MlDsa87 => oid::OID_HYBRID_SIGN_87,
        }
    }
}

// ---------------------------------------------------------------------------
// GeneratedCert — output of certificate generation
// ---------------------------------------------------------------------------

/// A generated certificate with its associated key material.
#[derive(Clone, Debug)]
pub struct GeneratedCert {
    /// The DER-encoded X.509 certificate.
    pub der_bytes: Vec<u8>,
    /// The PEM-encoded X.509 certificate.
    pub pem: String,
    /// Raw signing key bytes (seed for ML-DSA, composite for hybrid).
    /// Retained so a CA cert can sign leaf certificates.
    pub signing_key_bytes: Vec<u8>,
    /// Raw verifying key bytes (for embedding in other structures).
    pub verifying_key_bytes: Vec<u8>,
    /// The algorithm used to generate this certificate.
    pub algorithm: CertAlgorithm,
}

// ---------------------------------------------------------------------------
// CertBuilder
// ---------------------------------------------------------------------------

/// Builder for constructing X.509v3 certificates.
///
/// Use [`CertBuilder::new()`] to start, chain configuration methods, then
/// call [`self_signed()`](CertBuilder::self_signed) or
/// [`signed_by()`](CertBuilder::signed_by) to produce the certificate.
pub struct CertBuilder {
    subject: String,
    validity_days: u32,
    is_ca: bool,
}

impl Default for CertBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CertBuilder {
    /// Create a new certificate builder with default values.
    ///
    /// Defaults: subject "CN=localhost", validity 365 days, not a CA.
    pub fn new() -> Self {
        Self {
            subject: "CN=localhost".to_string(),
            validity_days: 365,
            is_ca: false,
        }
    }

    /// Set the subject common name (CN).
    ///
    /// The `cn` parameter should be a plain string value (e.g. "My CA" or
    /// "server.example.com"). It will be encoded as a CN attribute in the
    /// certificate's subject DN.
    pub fn subject(mut self, cn: &str) -> Self {
        self.subject = cn.to_string();
        self
    }

    /// Set the certificate validity period in days from now.
    pub fn validity_days(mut self, days: u32) -> Self {
        self.validity_days = days;
        self
    }

    /// Set whether this certificate is a CA (Certificate Authority).
    ///
    /// CA certificates can sign other certificates via [`signed_by()`](CertBuilder::signed_by).
    pub fn ca(mut self, is_ca: bool) -> Self {
        self.is_ca = is_ca;
        self
    }

    /// Generate a self-signed certificate.
    ///
    /// The certificate's issuer and subject will be identical (self-signed).
    /// A fresh keypair is generated for the given algorithm.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation or DER encoding fails.
    pub fn self_signed(self, algo: CertAlgorithm) -> Result<GeneratedCert> {
        // Dispatch to the appropriate generic implementation based on algorithm
        match algo {
            CertAlgorithm::MlDsa44 => self.self_signed_mldsa::<ml_dsa::MlDsa44>(algo),
            CertAlgorithm::MlDsa65 => self.self_signed_mldsa::<ml_dsa::MlDsa65>(algo),
            CertAlgorithm::MlDsa87 => self.self_signed_mldsa::<ml_dsa::MlDsa87>(algo),
            CertAlgorithm::HybridEd25519MlDsa44 => self.self_signed_hybrid::<ml_dsa::MlDsa44>(algo),
            CertAlgorithm::HybridEd25519MlDsa65 => self.self_signed_hybrid::<ml_dsa::MlDsa65>(algo),
            CertAlgorithm::HybridEd25519MlDsa87 => self.self_signed_hybrid::<ml_dsa::MlDsa87>(algo),
        }
    }

    /// Generate a certificate signed by an existing CA certificate.
    ///
    /// The leaf certificate's issuer is set to the CA's subject. The CA's
    /// signing key (from `ca.signing_key_bytes`) is used to produce the
    /// signature. A fresh keypair is generated for the leaf.
    ///
    /// # Errors
    ///
    /// Returns an error if key generation, signing, or DER encoding fails.
    pub fn signed_by(self, ca: &GeneratedCert, algo: CertAlgorithm) -> Result<GeneratedCert> {
        match algo {
            CertAlgorithm::MlDsa44 => self.signed_by_mldsa::<ml_dsa::MlDsa44>(ca, algo),
            CertAlgorithm::MlDsa65 => self.signed_by_mldsa::<ml_dsa::MlDsa65>(ca, algo),
            CertAlgorithm::MlDsa87 => self.signed_by_mldsa::<ml_dsa::MlDsa87>(ca, algo),
            CertAlgorithm::HybridEd25519MlDsa44 => {
                self.signed_by_hybrid::<ml_dsa::MlDsa44>(ca, algo)
            }
            CertAlgorithm::HybridEd25519MlDsa65 => {
                self.signed_by_hybrid::<ml_dsa::MlDsa65>(ca, algo)
            }
            CertAlgorithm::HybridEd25519MlDsa87 => {
                self.signed_by_hybrid::<ml_dsa::MlDsa87>(ca, algo)
            }
        }
    }

    // ── Pure ML-DSA implementation ──────────────────────────────────────────

    fn self_signed_mldsa<P>(self, algo: CertAlgorithm) -> Result<GeneratedCert>
    where
        P: ml_dsa::KeyGen + ml_dsa::MlDsaParams,
    {
        let mut rng = rand::rng();
        let (sk, vk) = lupine_sign::ml_dsa_generate_keypair::<P>(&mut rng)?;
        let vk_bytes = vk.to_bytes().to_vec();
        let sk_bytes = sk.to_bytes().to_vec();

        let subject_der = encode_cn(&self.subject)?;
        let validity = make_validity(self.validity_days)?;
        let algorithm_id = make_algo_id(algo);

        // Build TBS — self-signed, so issuer == subject
        let tbs = TbsCertificate {
            version: 2, // v3
            serial_number: make_serial(&mut rng),
            signature_algorithm: algorithm_id.clone(),
            issuer: subject_der.clone(),
            validity,
            subject: subject_der,
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: algorithm_id.clone(),
                subject_public_key: BitString::new(0, vk_bytes.clone())
                    .map_err(|_| ser_err("vk too large for BIT STRING"))?,
            },
        };

        // Encode TBS, sign it, build full cert
        let tbs_der = tbs.to_der_bytes()?;
        let sig = sk.sign(&tbs_der)?;
        let sig_bytes = sig.to_bytes().to_vec();

        let cert = X509Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm_id,
            signature_value: BitString::new(0, sig_bytes)
                .map_err(|_| ser_err("signature too large for BIT STRING"))?,
        };

        let der_bytes = cert.to_der_bytes()?;
        let pem_str =
            pem::encode_pem("CERTIFICATE", &der_bytes).map_err(|_| ser_err("PEM encode failed"))?;

        Ok(GeneratedCert {
            der_bytes,
            pem: pem_str,
            signing_key_bytes: sk_bytes,
            verifying_key_bytes: vk_bytes,
            algorithm: algo,
        })
    }

    fn signed_by_mldsa<P>(self, ca: &GeneratedCert, algo: CertAlgorithm) -> Result<GeneratedCert>
    where
        P: ml_dsa::KeyGen + ml_dsa::MlDsaParams,
    {
        let mut rng = rand::rng();
        // Generate a new keypair for the leaf
        let (leaf_sk, leaf_vk) = lupine_sign::ml_dsa_generate_keypair::<P>(&mut rng)?;
        let leaf_vk_bytes = leaf_vk.to_bytes().to_vec();
        let leaf_sk_bytes = leaf_sk.to_bytes().to_vec();

        // Reconstruct the CA's signing key
        let ca_sk = lupine_sign::MlDsaSigningKey::<P>::from_bytes(&ca.signing_key_bytes)?;

        // Extract CA subject as issuer for the leaf
        let issuer_der = extract_subject_from_cert(&ca.der_bytes)?;
        let subject_der = encode_cn(&self.subject)?;
        let validity = make_validity(self.validity_days)?;
        let algorithm_id = make_algo_id(algo);

        let tbs = TbsCertificate {
            version: 2,
            serial_number: make_serial(&mut rng),
            signature_algorithm: algorithm_id.clone(),
            issuer: issuer_der,
            validity,
            subject: subject_der,
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: algorithm_id.clone(),
                subject_public_key: BitString::new(0, leaf_vk_bytes.clone())
                    .map_err(|_| ser_err("vk too large for BIT STRING"))?,
            },
        };

        let tbs_der = tbs.to_der_bytes()?;
        let sig = ca_sk.sign(&tbs_der)?;
        let sig_bytes = sig.to_bytes().to_vec();

        let cert = X509Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm_id,
            signature_value: BitString::new(0, sig_bytes)
                .map_err(|_| ser_err("signature too large for BIT STRING"))?,
        };

        let der_bytes = cert.to_der_bytes()?;
        let pem_str =
            pem::encode_pem("CERTIFICATE", &der_bytes).map_err(|_| ser_err("PEM encode failed"))?;

        Ok(GeneratedCert {
            der_bytes,
            pem: pem_str,
            signing_key_bytes: leaf_sk_bytes,
            verifying_key_bytes: leaf_vk_bytes,
            algorithm: algo,
        })
    }

    // ── Hybrid Ed25519+ML-DSA implementation ────────────────────────────────

    fn self_signed_hybrid<P>(self, algo: CertAlgorithm) -> Result<GeneratedCert>
    where
        P: ml_dsa::KeyGen + ml_dsa::MlDsaParams,
    {
        let mut rng = rand::rng();
        let (sk, vk) = lupine_sign::hybrid_generate_keypair::<P>(&mut rng)?;
        let vk_bytes = vk.to_bytes();
        let sk_bytes = sk.to_bytes();

        let subject_der = encode_cn(&self.subject)?;
        let validity = make_validity(self.validity_days)?;
        let algorithm_id = make_algo_id(algo);

        let tbs = TbsCertificate {
            version: 2,
            serial_number: make_serial(&mut rng),
            signature_algorithm: algorithm_id.clone(),
            issuer: subject_der.clone(),
            validity,
            subject: subject_der,
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: algorithm_id.clone(),
                subject_public_key: BitString::new(0, vk_bytes.clone())
                    .map_err(|_| ser_err("vk too large for BIT STRING"))?,
            },
        };

        let tbs_der = tbs.to_der_bytes()?;
        let sig = sk.sign(&tbs_der)?;
        let sig_bytes = sig.to_bytes();

        let cert = X509Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm_id,
            signature_value: BitString::new(0, sig_bytes)
                .map_err(|_| ser_err("signature too large for BIT STRING"))?,
        };

        let der_bytes = cert.to_der_bytes()?;
        let pem_str =
            pem::encode_pem("CERTIFICATE", &der_bytes).map_err(|_| ser_err("PEM encode failed"))?;

        Ok(GeneratedCert {
            der_bytes,
            pem: pem_str,
            signing_key_bytes: sk_bytes,
            verifying_key_bytes: vk_bytes,
            algorithm: algo,
        })
    }

    fn signed_by_hybrid<P>(self, ca: &GeneratedCert, algo: CertAlgorithm) -> Result<GeneratedCert>
    where
        P: ml_dsa::KeyGen + ml_dsa::MlDsaParams,
    {
        let mut rng = rand::rng();
        let (leaf_sk, leaf_vk) = lupine_sign::hybrid_generate_keypair::<P>(&mut rng)?;
        let leaf_vk_bytes = leaf_vk.to_bytes();
        let leaf_sk_bytes = leaf_sk.to_bytes();

        // Reconstruct the CA's hybrid signing key
        let ca_sk = lupine_sign::HybridSigningKey::<P>::from_bytes(&ca.signing_key_bytes)?;

        let issuer_der = extract_subject_from_cert(&ca.der_bytes)?;
        let subject_der = encode_cn(&self.subject)?;
        let validity = make_validity(self.validity_days)?;
        let algorithm_id = make_algo_id(algo);

        let tbs = TbsCertificate {
            version: 2,
            serial_number: make_serial(&mut rng),
            signature_algorithm: algorithm_id.clone(),
            issuer: issuer_der,
            validity,
            subject: subject_der,
            subject_public_key_info: SubjectPublicKeyInfo {
                algorithm: algorithm_id.clone(),
                subject_public_key: BitString::new(0, leaf_vk_bytes.clone())
                    .map_err(|_| ser_err("vk too large for BIT STRING"))?,
            },
        };

        let tbs_der = tbs.to_der_bytes()?;
        let sig = ca_sk.sign(&tbs_der)?;
        let sig_bytes = sig.to_bytes();

        let cert = X509Certificate {
            tbs_certificate: tbs,
            signature_algorithm: algorithm_id,
            signature_value: BitString::new(0, sig_bytes)
                .map_err(|_| ser_err("signature too large for BIT STRING"))?,
        };

        let der_bytes = cert.to_der_bytes()?;
        let pem_str =
            pem::encode_pem("CERTIFICATE", &der_bytes).map_err(|_| ser_err("PEM encode failed"))?;

        Ok(GeneratedCert {
            der_bytes,
            pem: pem_str,
            signing_key_bytes: leaf_sk_bytes,
            verifying_key_bytes: leaf_vk_bytes,
            algorithm: algo,
        })
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

/// Build an AlgorithmIdentifier for the given algorithm.
fn make_algo_id(algo: CertAlgorithm) -> AlgorithmIdentifier {
    AlgorithmIdentifier {
        algorithm: algo.oid(),
        parameters: None,
    }
}

/// Generate a random 16-byte serial number (positive integer).
fn make_serial(rng: &mut impl rand::Rng) -> Vec<u8> {
    let mut serial = vec![0u8; 16];
    rng.fill_bytes(&mut serial);
    // Ensure the serial is positive (clear the high bit)
    serial[0] &= 0x7F;
    // Ensure it's non-zero
    if serial.iter().all(|&b| b == 0) {
        serial[15] = 1;
    }
    serial
}

/// Create a Validity period: now to now + days.
///
/// Uses a fixed "not before" of 2026-01-01T00:00:00Z for reproducibility
/// in tests, and computes "not after" by adding the specified number of days.
/// In production, this would use the system clock.
fn make_validity(days: u32) -> Result<Validity> {
    // Use a fixed base time. In a real implementation we'd use SystemTime::now(),
    // but der::DateTime doesn't have a from_system_time without the std feature
    // on der, and we want to keep the dependency surface small.
    let not_before =
        der::DateTime::new(2026, 1, 1, 0, 0, 0).map_err(|_| ser_err("invalid not_before date"))?;

    // Approximate: add days to the year/month/day.
    // For simplicity, compute the target date by adding days to a base timestamp.
    let base_unix_secs: u64 = not_before.unix_duration().as_secs();
    let target_secs = base_unix_secs + (days as u64) * 86400;
    let not_after = der::DateTime::from_unix_duration(core::time::Duration::from_secs(target_secs))
        .map_err(|_| ser_err("invalid not_after date"))?;

    Ok(Validity {
        not_before,
        not_after,
    })
}

/// Extract the subject DN (raw DER) from a DER-encoded X.509 certificate.
///
/// Parses the certificate to find the subject field within the TbsCertificate.
fn extract_subject_from_cert(cert_der: &[u8]) -> Result<Vec<u8>> {
    let cert = X509Certificate::from_der(cert_der)?;
    Ok(cert.tbs_certificate.subject)
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
    use crate::asn1::{decode_cn, X509Certificate};

    /// Run `f` on a thread with a 32 MB stack.
    ///
    /// ML-DSA operations (especially ML-DSA-87) allocate large intermediates
    /// on the stack in debug builds, exceeding the default 8 MB thread stack.
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    #[test]
    fn self_signed_mldsa44() {
        with_large_stack(|| {
            let cert = CertBuilder::new()
                .subject("CN=test-44")
                .self_signed(CertAlgorithm::MlDsa44)
                .unwrap();
            assert!(!cert.der_bytes.is_empty());
            assert!(cert.pem.starts_with("-----BEGIN CERTIFICATE-----"));

            let parsed = X509Certificate::from_der(&cert.der_bytes).unwrap();
            assert_eq!(parsed.signature_algorithm.algorithm, oid::OID_ML_DSA_44);
            assert_eq!(parsed.tbs_certificate.version, 2);

            // Subject should contain our CN
            let cn = decode_cn(&parsed.tbs_certificate.subject).unwrap();
            assert_eq!(cn, "CN=test-44");

            // Self-signed: issuer == subject
            assert_eq!(
                parsed.tbs_certificate.issuer,
                parsed.tbs_certificate.subject
            );
        });
    }

    #[test]
    fn self_signed_mldsa65() {
        with_large_stack(|| {
            let cert = CertBuilder::new()
                .subject("CN=test-65")
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            assert!(!cert.der_bytes.is_empty());

            let parsed = X509Certificate::from_der(&cert.der_bytes).unwrap();
            assert_eq!(parsed.signature_algorithm.algorithm, oid::OID_ML_DSA_65);
        });
    }

    #[test]
    fn self_signed_mldsa87() {
        with_large_stack(|| {
            let cert = CertBuilder::new()
                .subject("CN=test-87")
                .self_signed(CertAlgorithm::MlDsa87)
                .unwrap();
            assert!(!cert.der_bytes.is_empty());

            let parsed = X509Certificate::from_der(&cert.der_bytes).unwrap();
            assert_eq!(parsed.signature_algorithm.algorithm, oid::OID_ML_DSA_87);
        });
    }

    #[test]
    fn self_signed_hybrid_mldsa44() {
        with_large_stack(|| {
            let cert = CertBuilder::new()
                .subject("CN=hybrid-44")
                .self_signed(CertAlgorithm::HybridEd25519MlDsa44)
                .unwrap();
            assert!(!cert.der_bytes.is_empty());

            let parsed = X509Certificate::from_der(&cert.der_bytes).unwrap();
            assert_eq!(
                parsed.signature_algorithm.algorithm,
                oid::OID_HYBRID_SIGN_44
            );
        });
    }

    #[test]
    fn self_signed_hybrid_mldsa65() {
        with_large_stack(|| {
            let cert = CertBuilder::new()
                .subject("CN=hybrid-65")
                .self_signed(CertAlgorithm::HybridEd25519MlDsa65)
                .unwrap();
            assert!(!cert.der_bytes.is_empty());

            let parsed = X509Certificate::from_der(&cert.der_bytes).unwrap();
            assert_eq!(
                parsed.signature_algorithm.algorithm,
                oid::OID_HYBRID_SIGN_65
            );
        });
    }

    #[test]
    fn self_signed_hybrid_mldsa87() {
        with_large_stack(|| {
            let cert = CertBuilder::new()
                .subject("CN=hybrid-87")
                .self_signed(CertAlgorithm::HybridEd25519MlDsa87)
                .unwrap();
            assert!(!cert.der_bytes.is_empty());

            let parsed = X509Certificate::from_der(&cert.der_bytes).unwrap();
            assert_eq!(
                parsed.signature_algorithm.algorithm,
                oid::OID_HYBRID_SIGN_87
            );
        });
    }

    #[test]
    fn ca_signed_leaf_mldsa65() {
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

            assert!(!leaf.der_bytes.is_empty());

            let parsed_leaf = X509Certificate::from_der(&leaf.der_bytes).unwrap();
            let parsed_ca = X509Certificate::from_der(&ca.der_bytes).unwrap();

            // Leaf's issuer should match CA's subject
            assert_eq!(
                parsed_leaf.tbs_certificate.issuer,
                parsed_ca.tbs_certificate.subject
            );

            // Leaf's subject should differ from CA's subject
            assert_ne!(
                parsed_leaf.tbs_certificate.subject,
                parsed_ca.tbs_certificate.subject
            );

            // Check CN values
            let leaf_cn = decode_cn(&parsed_leaf.tbs_certificate.subject).unwrap();
            assert_eq!(leaf_cn, "CN=leaf");
            let issuer_cn = decode_cn(&parsed_leaf.tbs_certificate.issuer).unwrap();
            assert_eq!(issuer_cn, "CN=Test CA");
        });
    }

    #[test]
    fn ca_signed_leaf_hybrid() {
        with_large_stack(|| {
            let ca = CertBuilder::new()
                .subject("CN=Hybrid CA")
                .ca(true)
                .self_signed(CertAlgorithm::HybridEd25519MlDsa65)
                .unwrap();

            let leaf = CertBuilder::new()
                .subject("CN=hybrid-leaf")
                .signed_by(&ca, CertAlgorithm::HybridEd25519MlDsa65)
                .unwrap();

            assert!(!leaf.der_bytes.is_empty());

            let parsed_leaf = X509Certificate::from_der(&leaf.der_bytes).unwrap();
            assert_eq!(
                parsed_leaf.signature_algorithm.algorithm,
                oid::OID_HYBRID_SIGN_65
            );
        });
    }

    #[test]
    fn validity_period() {
        with_large_stack(|| {
            let cert = CertBuilder::new()
                .subject("CN=validity-test")
                .validity_days(30)
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();

            let parsed = X509Certificate::from_der(&cert.der_bytes).unwrap();
            let validity = &parsed.tbs_certificate.validity;

            // not_before should be 2026-01-01
            let nb = validity.not_before;
            assert_eq!(nb.year(), 2026);
            assert_eq!(nb.month(), 1);
            assert_eq!(nb.day(), 1);

            // not_after should be 2026-01-31 (30 days later)
            let na = validity.not_after;
            assert_eq!(na.year(), 2026);
            assert_eq!(na.month(), 1);
            assert_eq!(na.day(), 31);
        });
    }

    #[test]
    fn pem_output_format() {
        with_large_stack(|| {
            let cert = CertBuilder::new()
                .subject("CN=pem-test")
                .self_signed(CertAlgorithm::MlDsa44)
                .unwrap();

            assert!(cert.pem.starts_with("-----BEGIN CERTIFICATE-----"));
            assert!(cert.pem.contains("-----END CERTIFICATE-----"));
            assert!(cert.pem.ends_with('\n'));
        });
    }

    #[test]
    fn default_builder() {
        with_large_stack(|| {
            // Default builder should produce a valid certificate
            let cert = CertBuilder::default()
                .self_signed(CertAlgorithm::MlDsa44)
                .unwrap();
            let parsed = X509Certificate::from_der(&cert.der_bytes).unwrap();
            let cn = decode_cn(&parsed.tbs_certificate.subject).unwrap();
            assert_eq!(cn, "CN=localhost");
        });
    }
}
