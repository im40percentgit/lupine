//! Certificate chain validation — signature verification for X.509 chains.
//!
//! Provides [`verify_self_signed`] for checking a self-signed certificate's
//! signature against its own public key, and [`verify_chain`] for validating
//! a chain from leaf to root.
//!
//! # Example
//!
//! ```rust,ignore
//! use lupine_cert::parse::Certificate;
//! use lupine_cert::validate::{verify_self_signed, verify_chain};
//!
//! let root = Certificate::from_pem(&root_pem)?;
//! verify_self_signed(&root)?;
//!
//! let leaf = Certificate::from_pem(&leaf_pem)?;
//! verify_chain(&[leaf, root])?;
//! ```
//!
//! @decision DEC-CERT-004
//! @title OID-based signature dispatch in validate vs trait-based generics
//! @status accepted
//! @rationale Signature verification must dispatch on the OID embedded in the
//!   certificate. A match on the OID to concrete ML-DSA parameter sets or
//!   hybrid types is simpler and more readable than a trait-object approach.
//!   This mirrors the dispatch pattern in `generate.rs` and keeps the code
//!   greppable: each supported algorithm has an explicit match arm.

use der::asn1::ObjectIdentifier;
use lupine_core::{Error, Result, SerializationError};
use lupine_serial::oid;
use lupine_sign::{HybridSignature, HybridVerifyingKey, MlDsaSignature, MlDsaVerifyingKey};

use crate::parse::Certificate;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Verify a self-signed certificate's signature against its own public key.
///
/// Checks that the certificate's `signature_bytes` verify against its own
/// `public_key_bytes` over its `tbs_bytes`, using the algorithm identified
/// by `signature_algorithm_oid`.
///
/// # Errors
///
/// Returns an error if:
/// - The signature algorithm OID is unrecognized
/// - The public key bytes cannot be parsed for the algorithm
/// - The signature is invalid
pub fn verify_self_signed(cert: &Certificate) -> Result<()> {
    verify_signature(
        cert.signature_algorithm_oid(),
        cert.public_key_bytes(),
        cert.tbs_bytes(),
        cert.signature_bytes(),
    )
}

/// Verify a certificate chain from leaf to root.
///
/// `certs[0]` is the leaf certificate, `certs[last]` is the root (trust
/// anchor). The root must be self-signed.
///
/// For each adjacent pair `(cert, issuer)`, verifies that `cert`'s signature
/// was produced by `issuer`'s public key over `cert`'s TBS bytes.
///
/// # Errors
///
/// Returns an error if:
/// - The chain is empty
/// - The root is not validly self-signed
/// - Any intermediate signature verification fails
/// - Any algorithm OID is unrecognized
pub fn verify_chain(certs: &[Certificate]) -> Result<()> {
    if certs.is_empty() {
        return Err(ser_err("empty certificate chain"));
    }

    // Root (last cert) must be self-signed.
    let root = &certs[certs.len() - 1];
    verify_self_signed(root)?;

    // Verify each (cert, issuer) pair from leaf toward root.
    for i in 0..certs.len() - 1 {
        let cert = &certs[i];
        let issuer = &certs[i + 1];
        verify_signature(
            cert.signature_algorithm_oid(),
            issuer.public_key_bytes(),
            cert.tbs_bytes(),
            cert.signature_bytes(),
        )?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Signature verification dispatch
// ---------------------------------------------------------------------------

/// Verify a signature given an algorithm OID, raw verifying key bytes, the
/// signed message, and raw signature bytes.
///
/// Dispatches to the correct ML-DSA parameter set or hybrid Ed25519+ML-DSA
/// type based on the OID.
fn verify_signature(
    algorithm_oid: &ObjectIdentifier,
    vk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    // Try pure ML-DSA first.
    if let Some(sign_algo) = oid::sign_from_oid(algorithm_oid) {
        return verify_mldsa(sign_algo, vk_bytes, message, sig_bytes);
    }

    // Try hybrid Ed25519+ML-DSA.
    if *algorithm_oid == oid::OID_HYBRID_SIGN_44 {
        return verify_hybrid::<ml_dsa::MlDsa44>(vk_bytes, message, sig_bytes);
    }
    if *algorithm_oid == oid::OID_HYBRID_SIGN_65 {
        return verify_hybrid::<ml_dsa::MlDsa65>(vk_bytes, message, sig_bytes);
    }
    if *algorithm_oid == oid::OID_HYBRID_SIGN_87 {
        return verify_hybrid::<ml_dsa::MlDsa87>(vk_bytes, message, sig_bytes);
    }

    Err(ser_err("unrecognized signature algorithm OID"))
}

/// Verify a pure ML-DSA signature.
fn verify_mldsa(
    algo: lupine_core::SignAlgorithm,
    vk_bytes: &[u8],
    message: &[u8],
    sig_bytes: &[u8],
) -> Result<()> {
    use lupine_core::SignAlgorithm;
    match algo {
        SignAlgorithm::MlDsa44 => {
            verify_mldsa_generic::<ml_dsa::MlDsa44>(vk_bytes, message, sig_bytes)
        }
        SignAlgorithm::MlDsa65 => {
            verify_mldsa_generic::<ml_dsa::MlDsa65>(vk_bytes, message, sig_bytes)
        }
        SignAlgorithm::MlDsa87 => {
            verify_mldsa_generic::<ml_dsa::MlDsa87>(vk_bytes, message, sig_bytes)
        }
        // SLH-DSA is not supported for certificates (signatures are too large).
        _ => Err(ser_err("unsupported signature algorithm for certificates")),
    }
}

/// Verify an ML-DSA signature with a specific parameter set.
fn verify_mldsa_generic<P>(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()>
where
    P: ml_dsa::MlDsaParams,
{
    let vk = MlDsaVerifyingKey::<P>::from_bytes(vk_bytes)?;
    let sig = MlDsaSignature::<P>::from_bytes(sig_bytes)?;
    vk.verify(message, &sig)
}

/// Verify a hybrid Ed25519+ML-DSA signature with a specific parameter set.
fn verify_hybrid<P>(vk_bytes: &[u8], message: &[u8], sig_bytes: &[u8]) -> Result<()>
where
    P: ml_dsa::MlDsaParams,
{
    let vk = HybridVerifyingKey::<P>::from_bytes(vk_bytes)?;
    let sig = HybridSignature::<P>::from_bytes(sig_bytes)?;
    vk.verify(message, &sig)
}

// ---------------------------------------------------------------------------
// Helpers
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
    fn verify_self_signed_mldsa44() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=verify-44")
                .self_signed(CertAlgorithm::MlDsa44)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert!(verify_self_signed(&cert).is_ok());
        });
    }

    #[test]
    fn verify_self_signed_mldsa65() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=verify-test")
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert!(verify_self_signed(&cert).is_ok());
        });
    }

    #[test]
    fn verify_self_signed_mldsa87() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=verify-87")
                .self_signed(CertAlgorithm::MlDsa87)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert!(verify_self_signed(&cert).is_ok());
        });
    }

    #[test]
    fn verify_chain_ca_leaf() {
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

            let ca_cert = Certificate::from_der(&ca.der_bytes).unwrap();
            let leaf_cert = Certificate::from_der(&leaf.der_bytes).unwrap();

            assert!(verify_chain(&[leaf_cert, ca_cert]).is_ok());
        });
    }

    #[test]
    fn verify_wrong_issuer_fails() {
        with_large_stack(|| {
            let ca1 = CertBuilder::new()
                .subject("CN=CA1")
                .ca(true)
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            let ca2 = CertBuilder::new()
                .subject("CN=CA2")
                .ca(true)
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            let leaf = CertBuilder::new()
                .subject("CN=leaf")
                .signed_by(&ca1, CertAlgorithm::MlDsa65)
                .unwrap();

            let ca2_cert = Certificate::from_der(&ca2.der_bytes).unwrap();
            let leaf_cert = Certificate::from_der(&leaf.der_bytes).unwrap();

            assert!(verify_chain(&[leaf_cert, ca2_cert]).is_err());
        });
    }

    #[test]
    fn verify_hybrid_self_signed_44() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=hybrid-44")
                .self_signed(CertAlgorithm::HybridEd25519MlDsa44)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert!(verify_self_signed(&cert).is_ok());
        });
    }

    #[test]
    fn verify_hybrid_self_signed_65() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=hybrid")
                .self_signed(CertAlgorithm::HybridEd25519MlDsa65)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert!(verify_self_signed(&cert).is_ok());
        });
    }

    #[test]
    fn verify_hybrid_self_signed_87() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=hybrid-87")
                .self_signed(CertAlgorithm::HybridEd25519MlDsa87)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            assert!(verify_self_signed(&cert).is_ok());
        });
    }

    #[test]
    fn verify_hybrid_chain() {
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

            let ca_cert = Certificate::from_der(&ca.der_bytes).unwrap();
            let leaf_cert = Certificate::from_der(&leaf.der_bytes).unwrap();

            assert!(verify_chain(&[leaf_cert, ca_cert]).is_ok());
        });
    }

    #[test]
    fn verify_empty_chain_fails() {
        assert!(verify_chain(&[]).is_err());
    }

    #[test]
    fn verify_single_self_signed_chain() {
        with_large_stack(|| {
            let gen = CertBuilder::new()
                .subject("CN=single")
                .self_signed(CertAlgorithm::MlDsa65)
                .unwrap();
            let cert = Certificate::from_der(&gen.der_bytes).unwrap();
            // A single self-signed cert is a valid chain of length 1.
            assert!(verify_chain(&[cert]).is_ok());
        });
    }
}
