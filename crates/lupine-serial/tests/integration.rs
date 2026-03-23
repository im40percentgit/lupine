//! Integration tests for lupine-serial cross-format encoding chains.
//!
//! Tests are split into two sections:
//!
//! 1. **Synthetic-byte tests** — fast tests using fake key bytes. These verify
//!    that the DER/PEM/SPKI encoding layers compose correctly as a format chain.
//!
//! 2. **Real-key tests** — slower tests using actual ML-KEM keypairs. These
//!    verify that round-tripping a real key through DER/PEM/SPKI encoding and
//!    decoding does not corrupt the key material needed for crypto operations.
//!
//! @decision DEC-SERIAL-006
//! @title Integration test scope: synthetic bytes + real ML-KEM keys
//! @status accepted
//! @rationale The synthetic-byte tests validate the serialization format chain
//!   quickly (no keygen cost). The real-key tests validate end-to-end: that
//!   the extracted raw bytes from DER/SPKI decoding exactly match the original
//!   key, so a subsequent `from_bytes` call reconstructs a working key.
//!   lupine-sign real-key tests are not included here because lupine-sign uses
//!   rand 0.10 RC which has a different CryptoRng trait than rand 0.8 (used by
//!   lupine-kem and this crate's dev-dep). Cross-format testing of lupine-sign
//!   keys is covered in lupine-sign/tests/roundtrip.rs.

use lupine_core::{KemAlgorithm, SignAlgorithm};
use lupine_serial::composite::{CompositeKemVariant, CompositeSignVariant};
use lupine_serial::{composite, der, pem, spki};

// Imports for real-key tests (Section 2)
use lupine_kem::{generate_keypair as kem_generate_keypair, MlKemPublicKey, MlKemSecretKey};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore,
};
use rand::rngs::OsRng;

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
        let der = composite::encode_composite_kem_key(variant, CLASSICAL_COMPONENT, PQC_COMPONENT)
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
        let der = composite::encode_composite_sign_key(variant, CLASSICAL_COMPONENT, PQC_COMPONENT)
            .unwrap();
        let (v, c, p) = composite::decode_composite_sign_key(&der).unwrap();
        assert_eq!(v, variant);
        assert_eq!(c, CLASSICAL_COMPONENT);
        assert_eq!(p, PQC_COMPONENT);
    }
}

// ---------------------------------------------------------------------------
// Section 2: Real-key integration tests (ML-KEM)
//
// These tests generate actual ML-KEM keypairs, serialize through the
// DER/PEM/SPKI pipeline, reconstruct keys from the recovered bytes, and
// verify that cryptographic operations still work end-to-end.
//
// lupine-sign real-key tests are in lupine-sign/tests/roundtrip.rs because
// lupine-sign uses rand 0.10 (RC), which has a different CryptoRng trait than
// the rand 0.8 used by lupine-kem and this integration test.
// ---------------------------------------------------------------------------

/// Helper: generate an ML-KEM keypair and run a full serialize→deserialize→
/// crypto cycle through DER/PEM/DER encoding.
fn kem_real_key_der_pem_cycle<P>(alg: KemAlgorithm)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    // Generate a real keypair.
    let (sk, pk) = kem_generate_keypair::<P>(&mut OsRng).expect("real keygen must succeed");

    // --- Public key: DER → PEM → DER → raw bytes → from_bytes ---
    let pk_raw = pk.to_bytes();
    let pk_der = der::encode_kem_public_key_der(alg, pk_raw).expect("encode pk DER must succeed");
    let pk_pem = pem::encode_public_key_pem(&pk_der).expect("encode pk PEM must succeed");
    let pk_der2 = pem::decode_public_key_pem(&pk_pem).expect("decode pk PEM must succeed");
    let (alg_out, pk_raw2) =
        der::decode_kem_public_key_der(&pk_der2).expect("decode pk DER must succeed");

    assert_eq!(alg_out, alg, "algorithm must survive DER/PEM round-trip");
    assert_eq!(
        pk_raw,
        pk_raw2.as_slice(),
        "pk raw bytes must survive DER/PEM round-trip"
    );

    // Reconstruct the public key from the round-tripped bytes.
    let pk2 = MlKemPublicKey::<P>::from_bytes(&pk_raw2).expect("pk from_bytes must succeed");
    assert_eq!(
        pk.to_bytes(),
        pk2.to_bytes(),
        "pk must be identical after DER/PEM round-trip"
    );

    // --- Secret key: DER → PEM → DER → raw bytes → from_bytes ---
    let sk_raw = sk.to_bytes();
    let sk_der = der::encode_kem_secret_key_der(alg, sk_raw).expect("encode sk DER must succeed");
    let sk_pem = pem::encode_private_key_pem(&sk_der).expect("encode sk PEM must succeed");
    let sk_der2 = pem::decode_private_key_pem(&sk_pem).expect("decode sk PEM must succeed");
    let (alg_sk_out, sk_raw2) =
        der::decode_kem_secret_key_der(&sk_der2).expect("decode sk DER must succeed");

    assert_eq!(alg_sk_out, alg, "algorithm must survive DER/PEM round-trip");
    assert_eq!(
        sk_raw,
        sk_raw2.as_slice(),
        "sk raw bytes must survive DER/PEM round-trip"
    );

    let sk2 = MlKemSecretKey::<P>::from_bytes(&sk_raw2).expect("sk from_bytes must succeed");
    assert_eq!(
        sk.to_bytes(),
        sk2.to_bytes(),
        "sk must be identical after DER/PEM round-trip"
    );

    // --- Crypto: use the round-tripped keys for a full encap+decap cycle ---
    let (ct, ss_send) = pk2
        .encapsulate(&mut OsRng)
        .expect("encap with DER/PEM-recovered pk must succeed");
    let ss_recv = sk2
        .decapsulate(&ct)
        .expect("decap with DER/PEM-recovered sk must succeed");
    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "shared secrets must match after DER/PEM key round-trip"
    );
}

#[test]
fn real_key_mlkem512_der_pem_crypto_cycle() {
    kem_real_key_der_pem_cycle::<ml_kem::MlKem512>(KemAlgorithm::MlKem512);
}

#[test]
fn real_key_mlkem768_der_pem_crypto_cycle() {
    kem_real_key_der_pem_cycle::<ml_kem::MlKem768>(KemAlgorithm::MlKem768);
}

#[test]
fn real_key_mlkem1024_der_pem_crypto_cycle() {
    kem_real_key_der_pem_cycle::<ml_kem::MlKem1024>(KemAlgorithm::MlKem1024);
}

/// Real-key SPKI round-trip: public key → SPKI DER → PEM → SPKI DER → raw →
/// reconstruct → crypto works.
fn kem_real_key_spki_cycle<P>(alg: KemAlgorithm)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = kem_generate_keypair::<P>(&mut OsRng).expect("real keygen must succeed");

    let pk_raw = pk.to_bytes();
    let spki_der = spki::encode_kem_spki(alg, pk_raw).expect("encode SPKI must succeed");
    let spki_pem = pem::encode_public_key_pem(&spki_der).expect("encode SPKI PEM must succeed");
    let spki_der2 = pem::decode_public_key_pem(&spki_pem).expect("decode SPKI PEM must succeed");
    let (alg_out, pk_raw2) = spki::decode_kem_spki(&spki_der2).expect("decode SPKI must succeed");

    assert_eq!(alg_out, alg, "algorithm must survive SPKI/PEM round-trip");
    assert_eq!(
        pk_raw,
        pk_raw2.as_slice(),
        "pk bytes must survive SPKI/PEM round-trip"
    );

    let pk2 = MlKemPublicKey::<P>::from_bytes(&pk_raw2).expect("pk from_bytes must succeed");
    let (ct, ss_send) = pk2
        .encapsulate(&mut OsRng)
        .expect("encap with SPKI-recovered pk must succeed");
    let ss_recv = sk.decapsulate(&ct).expect("decap must succeed");
    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "shared secrets must match after SPKI/PEM key round-trip"
    );
}

#[test]
fn real_key_mlkem512_spki_cycle() {
    kem_real_key_spki_cycle::<ml_kem::MlKem512>(KemAlgorithm::MlKem512);
}

#[test]
fn real_key_mlkem768_spki_cycle() {
    kem_real_key_spki_cycle::<ml_kem::MlKem768>(KemAlgorithm::MlKem768);
}

#[test]
fn real_key_mlkem1024_spki_cycle() {
    kem_real_key_spki_cycle::<ml_kem::MlKem1024>(KemAlgorithm::MlKem1024);
}

/// Real-key full pipeline: DER → SPKI → PEM all use the same underlying raw
/// bytes for the same keypair, so they must all decode to identical byte slices.
#[test]
fn real_key_mlkem768_der_and_spki_recover_same_raw_bytes() {
    let (_sk, pk) = kem_generate_keypair::<ml_kem::MlKem768>(&mut OsRng).unwrap();
    let pk_raw = pk.to_bytes();

    // DER encoding
    let der_bytes = der::encode_kem_public_key_der(KemAlgorithm::MlKem768, pk_raw).unwrap();
    let (_, from_der) = der::decode_kem_public_key_der(&der_bytes).unwrap();

    // SPKI encoding
    let spki_bytes = spki::encode_kem_spki(KemAlgorithm::MlKem768, pk_raw).unwrap();
    let (_, from_spki) = spki::decode_kem_spki(&spki_bytes).unwrap();

    // Both must recover the identical raw bytes.
    assert_eq!(
        from_der.as_slice(),
        pk_raw,
        "DER-decoded raw bytes must match original pk"
    );
    assert_eq!(
        from_spki.as_slice(),
        pk_raw,
        "SPKI-decoded raw bytes must match original pk"
    );
    assert_eq!(
        from_der, from_spki,
        "DER and SPKI must decode to identical raw key bytes"
    );
}
