//! Integration tests for lupine-serial cross-format encoding chains.
//!
//! These tests exercise the full path: raw key bytes → DER → PEM → DER → key,
//! and DER → SPKI → decode, verifying that all modules compose correctly.
//!
//! @decision DEC-SERIAL-006
//! @title Integration test scope: synthetic bytes vs real cryptographic keys
//! @status accepted
//! @rationale Integration tests here use short synthetic byte slices rather
//!   than real ML-KEM/ML-DSA keypairs. The serialisation layer is format-only:
//!   it wraps arbitrary bytes in DER/PEM/SPKI frames. Generating real keypairs
//!   would add multi-second test time (SLH-DSA key generation especially) with
//!   no additional coverage of the serialisation code paths. Crypto correctness
//!   is tested in lupine-kem and lupine-sign respectively. The integration tests
//!   verify composition: that the DER, PEM, SPKI, and composite modules
//!   interoperate correctly as a chain.

use lupine_core::{KemAlgorithm, SignAlgorithm};
use lupine_serial::composite::{CompositeKemVariant, CompositeSignVariant};
use lupine_serial::{composite, der, pem, spki};

// Synthetic key bytes — large enough to be realistic-ish but not actual keys.
const FAKE_KEM_KEY: &[u8] = b"fake_kem_public_key_bytes_for_integration_tests_roundtrip";
const FAKE_SIGN_KEY: &[u8] = b"fake_sign_verifying_key_bytes_for_integration_tests";
const FAKE_SECRET_KEY: &[u8] = b"fake_secret_key_bytes_for_integration_tests_roundtrip_xx";
const FAKE_SIG: &[u8] = b"fake_signature_bytes_for_integration_test_roundtrip";
const CLASSICAL_COMPONENT: &[u8] = b"classical_x25519_or_ed25519_component_32_bytes";
const PQC_COMPONENT: &[u8] = b"pqc_ml_kem_or_ml_dsa_component_bytes_placeholder";

// ---------------------------------------------------------------------------
// Cross-format: key → DER → PEM → DER → key
// ---------------------------------------------------------------------------

#[test]
fn kem_public_key_der_pem_der_roundtrip() {
    let alg = KemAlgorithm::MlKem768;
    let der_bytes = der::encode_kem_public_key_der(alg, FAKE_KEM_KEY).unwrap();
    let pem_str = pem::encode_public_key_pem(&der_bytes).unwrap();
    assert!(pem_str.starts_with("-----BEGIN PUBLIC KEY-----"));
    let der_recovered = pem::decode_public_key_pem(&pem_str).unwrap();
    assert_eq!(der_bytes, der_recovered);
    let (alg_out, key_out) = der::decode_kem_public_key_der(&der_recovered).unwrap();
    assert_eq!(alg_out, alg);
    assert_eq!(key_out, FAKE_KEM_KEY);
}

#[test]
fn kem_secret_key_der_pem_der_roundtrip() {
    let alg = KemAlgorithm::MlKem512;
    let der_bytes = der::encode_kem_secret_key_der(alg, FAKE_SECRET_KEY).unwrap();
    let pem_str = pem::encode_private_key_pem(&der_bytes).unwrap();
    assert!(pem_str.starts_with("-----BEGIN PRIVATE KEY-----"));
    let der_recovered = pem::decode_private_key_pem(&pem_str).unwrap();
    let (alg_out, key_out) = der::decode_kem_secret_key_der(&der_recovered).unwrap();
    assert_eq!(alg_out, alg);
    assert_eq!(key_out, FAKE_SECRET_KEY);
}

#[test]
fn sign_public_key_der_pem_der_roundtrip() {
    let alg = SignAlgorithm::MlDsa65;
    let der_bytes = der::encode_sign_public_key_der(alg, FAKE_SIGN_KEY).unwrap();
    let pem_str = pem::encode_public_key_pem(&der_bytes).unwrap();
    let der_recovered = pem::decode_public_key_pem(&pem_str).unwrap();
    let (alg_out, key_out) = der::decode_sign_public_key_der(&der_recovered).unwrap();
    assert_eq!(alg_out, alg);
    assert_eq!(key_out, FAKE_SIGN_KEY);
}

#[test]
fn signature_der_pem_der_roundtrip() {
    let alg = SignAlgorithm::SlhDsaSha2128s;
    let der_bytes = der::encode_signature_der(alg, FAKE_SIG).unwrap();
    let pem_str = pem::encode_signature_pem(&der_bytes).unwrap();
    assert!(pem_str.starts_with("-----BEGIN SIGNATURE-----"));
    let der_recovered = pem::decode_signature_pem(&pem_str).unwrap();
    let (alg_out, sig_out) = der::decode_signature_der(&der_recovered).unwrap();
    assert_eq!(alg_out, alg);
    assert_eq!(sig_out, FAKE_SIG);
}

// ---------------------------------------------------------------------------
// Cross-format: key → SPKI → PEM → SPKI → key
// ---------------------------------------------------------------------------

#[test]
fn kem_spki_pem_roundtrip() {
    let alg = KemAlgorithm::MlKem1024;
    let spki_der = spki::encode_kem_spki(alg, FAKE_KEM_KEY).unwrap();
    let pem_str = pem::encode_public_key_pem(&spki_der).unwrap();
    let spki_recovered = pem::decode_public_key_pem(&pem_str).unwrap();
    let (alg_out, key_out) = spki::decode_kem_spki(&spki_recovered).unwrap();
    assert_eq!(alg_out, alg);
    assert_eq!(key_out, FAKE_KEM_KEY);
}

#[test]
fn sign_spki_pem_roundtrip() {
    let alg = SignAlgorithm::MlDsa87;
    let spki_der = spki::encode_sign_spki(alg, FAKE_SIGN_KEY).unwrap();
    let pem_str = pem::encode_public_key_pem(&spki_der).unwrap();
    let spki_recovered = pem::decode_public_key_pem(&pem_str).unwrap();
    let (alg_out, key_out) = spki::decode_sign_spki(&spki_recovered).unwrap();
    assert_eq!(alg_out, alg);
    assert_eq!(key_out, FAKE_SIGN_KEY);
}

// ---------------------------------------------------------------------------
// Cross-format: composite → DER → PEM → DER → composite
// ---------------------------------------------------------------------------

#[test]
fn composite_kem_der_pem_roundtrip() {
    let variant = CompositeKemVariant::X25519MlKem768;
    let der_bytes =
        composite::encode_composite_kem_key(variant, CLASSICAL_COMPONENT, PQC_COMPONENT).unwrap();
    let pem_str = pem::encode_public_key_pem(&der_bytes).unwrap();
    let der_recovered = pem::decode_public_key_pem(&pem_str).unwrap();
    let (v_out, c_out, p_out) = composite::decode_composite_kem_key(&der_recovered).unwrap();
    assert_eq!(v_out, variant);
    assert_eq!(c_out, CLASSICAL_COMPONENT);
    assert_eq!(p_out, PQC_COMPONENT);
}

#[test]
fn composite_sign_key_der_pem_roundtrip() {
    let variant = CompositeSignVariant::Ed25519MlDsa65;
    let der_bytes =
        composite::encode_composite_sign_key(variant, CLASSICAL_COMPONENT, PQC_COMPONENT).unwrap();
    let pem_str = pem::encode_public_key_pem(&der_bytes).unwrap();
    let der_recovered = pem::decode_public_key_pem(&pem_str).unwrap();
    let (v_out, c_out, p_out) = composite::decode_composite_sign_key(&der_recovered).unwrap();
    assert_eq!(v_out, variant);
    assert_eq!(c_out, CLASSICAL_COMPONENT);
    assert_eq!(p_out, PQC_COMPONENT);
}

#[test]
fn composite_signature_der_pem_roundtrip() {
    let variant = CompositeSignVariant::Ed25519MlDsa87;
    let ed_sig = b"ed25519_signature_64_bytes_padded_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let ml_sig = b"ml_dsa_signature_component_bytes";
    let der_bytes = composite::encode_composite_signature(variant, ed_sig, ml_sig).unwrap();
    let pem_str = pem::encode_signature_pem(&der_bytes).unwrap();
    let der_recovered = pem::decode_signature_pem(&pem_str).unwrap();
    let (v_out, c_out, p_out) = composite::decode_composite_signature(&der_recovered).unwrap();
    assert_eq!(v_out, variant);
    assert_eq!(c_out.as_slice(), ed_sig.as_slice());
    assert_eq!(p_out.as_slice(), ml_sig.as_slice());
}

// ---------------------------------------------------------------------------
// Format discrimination: DER vs SPKI bytes must differ
// ---------------------------------------------------------------------------

#[test]
fn der_and_spki_produce_different_bytes_for_same_key() {
    let alg = KemAlgorithm::MlKem512;
    let der_bytes = der::encode_kem_public_key_der(alg, FAKE_KEM_KEY).unwrap();
    let spki_bytes = spki::encode_kem_spki(alg, FAKE_KEM_KEY).unwrap();
    // SPKI uses BIT STRING; plain DER uses OCTET STRING — bytes must differ.
    assert_ne!(der_bytes, spki_bytes);
}

#[test]
fn spki_bytes_do_not_decode_as_plain_der() {
    let alg = KemAlgorithm::MlKem768;
    let spki_bytes = spki::encode_kem_spki(alg, FAKE_KEM_KEY).unwrap();
    // Decoding SPKI bytes through the plain DER decoder must fail because the
    // inner tag is BIT STRING (0x03) rather than OCTET STRING (0x04).
    assert!(der::decode_kem_public_key_der(&spki_bytes).is_err());
}

// ---------------------------------------------------------------------------
// All KEM algorithms: DER + PEM roundtrip
// ---------------------------------------------------------------------------

#[test]
fn all_kem_algorithms_der_pem_roundtrip() {
    let algs = [
        KemAlgorithm::MlKem512,
        KemAlgorithm::MlKem768,
        KemAlgorithm::MlKem1024,
    ];
    for alg in algs {
        let der_bytes = der::encode_kem_public_key_der(alg, FAKE_KEM_KEY).unwrap();
        let pem_str = pem::encode_public_key_pem(&der_bytes).unwrap();
        let der_back = pem::decode_public_key_pem(&pem_str).unwrap();
        let (alg_out, key_out) = der::decode_kem_public_key_der(&der_back).unwrap();
        assert_eq!(alg_out, alg, "DER+PEM roundtrip failed for {alg:?}");
        assert_eq!(key_out, FAKE_KEM_KEY);
    }
}

// ---------------------------------------------------------------------------
// All sign algorithms: DER + PEM roundtrip
// ---------------------------------------------------------------------------

#[test]
fn all_sign_algorithms_der_pem_roundtrip() {
    let algs = [
        SignAlgorithm::MlDsa44,
        SignAlgorithm::MlDsa65,
        SignAlgorithm::MlDsa87,
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
    for alg in algs {
        let der_bytes = der::encode_sign_public_key_der(alg, FAKE_SIGN_KEY).unwrap();
        let pem_str = pem::encode_public_key_pem(&der_bytes).unwrap();
        let der_back = pem::decode_public_key_pem(&pem_str).unwrap();
        let (alg_out, key_out) = der::decode_sign_public_key_der(&der_back).unwrap();
        assert_eq!(alg_out, alg, "DER+PEM roundtrip failed for {alg:?}");
        assert_eq!(key_out, FAKE_SIGN_KEY);
    }
}

// ---------------------------------------------------------------------------
// All composite KEM variants: DER roundtrip
// ---------------------------------------------------------------------------

#[test]
fn all_composite_kem_variants_roundtrip() {
    let variants = [
        CompositeKemVariant::X25519MlKem512,
        CompositeKemVariant::X25519MlKem768,
        CompositeKemVariant::X25519MlKem1024,
    ];
    for variant in variants {
        let der =
            composite::encode_composite_kem_key(variant, CLASSICAL_COMPONENT, PQC_COMPONENT)
                .unwrap();
        let (v, c, p) = composite::decode_composite_kem_key(&der).unwrap();
        assert_eq!(v, variant);
        assert_eq!(c, CLASSICAL_COMPONENT);
        assert_eq!(p, PQC_COMPONENT);
    }
}

// ---------------------------------------------------------------------------
// All composite sign variants: DER roundtrip
// ---------------------------------------------------------------------------

#[test]
fn all_composite_sign_variants_roundtrip() {
    let variants = [
        CompositeSignVariant::Ed25519MlDsa44,
        CompositeSignVariant::Ed25519MlDsa65,
        CompositeSignVariant::Ed25519MlDsa87,
    ];
    for variant in variants {
        let der =
            composite::encode_composite_sign_key(variant, CLASSICAL_COMPONENT, PQC_COMPONENT)
                .unwrap();
        let (v, c, p) = composite::decode_composite_sign_key(&der).unwrap();
        assert_eq!(v, variant);
        assert_eq!(c, CLASSICAL_COMPONENT);
        assert_eq!(p, PQC_COMPONENT);
    }
}
