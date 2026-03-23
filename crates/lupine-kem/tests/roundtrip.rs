//! Roundtrip integration tests for lupine-kem.
//!
//! These tests are more comprehensive than the inline unit tests in `src/`,
//! covering:
//! - All 6 KEM algorithm variants (3 ML-KEM + 3 Hybrid X25519+ML-KEM)
//! - Full serialize→deserialize→re-use cycle (not just byte equality)
//! - Ciphertext tamper detection via bit-flip
//! - Wrong-key rejection
//! - Shared secret length invariant
//!
//! Unlike the KAT tests, these use OsRng to exercise the full key diversity
//! and catch issues that depend on specific key values.
//!
//! @decision DEC-TEST-KEM-002
//! @title Integration roundtrip tests separate from inline unit tests
//! @status accepted
//! @rationale Inline unit tests in src/ cover the basic API surface. These
//!   integration tests extend coverage to the serialize→deserialize→re-use
//!   cycle (ensuring round-tripped keys still encrypt/decrypt correctly) and
//!   test all parameter sets consistently in one place. The separation makes
//!   it easy to run just the integration suite for CI performance tuning.

use lupine_kem::{
    generate_keypair,
    hybrid::{self, HybridKemCiphertext, HybridKemPublicKey, HybridKemSecretKey},
    MlKemCiphertext, MlKemPublicKey, MlKemSecretKey,
};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore,
};
use rand::rngs::OsRng;

// ── ML-KEM roundtrip helpers ──────────────────────────────────────────────────

/// Full roundtrip: keygen → encap → decap → secrets match.
fn mlkem_basic_roundtrip<P>()
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen must succeed");
    let (ct, ss_send) = pk.encapsulate(&mut OsRng).expect("encap must succeed");
    let ss_recv = sk.decapsulate(&ct).expect("decap must succeed");
    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "shared secrets must match after roundtrip"
    );
    assert_eq!(
        ss_send.as_bytes().len(),
        32,
        "shared secret must be 32 bytes"
    );
}

/// Serialize public key → deserialize → encapsulate → original sk decapsulates.
///
/// This verifies the serialize→deserialize cycle preserves the key material
/// needed for successful encapsulation/decapsulation.
fn mlkem_pk_serialize_deserialize_roundtrip<P>()
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen must succeed");

    // Serialize the public key to bytes.
    let pk_bytes = pk.to_bytes().to_vec();

    // Deserialize into a fresh public key object.
    let pk2 = MlKemPublicKey::<P>::from_bytes(&pk_bytes).expect("pk from_bytes must succeed");
    assert_eq!(
        pk.to_bytes(),
        pk2.to_bytes(),
        "pk bytes must survive serialize→deserialize"
    );

    // Encapsulate using the deserialized public key.
    let (ct, ss_send) = pk2
        .encapsulate(&mut OsRng)
        .expect("encap from deserialized pk must succeed");

    // Decapsulate using the original secret key — must still work.
    let ss_recv = sk
        .decapsulate(&ct)
        .expect("decap with original sk must succeed");
    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "shared secrets must match after pk serialize→deserialize cycle"
    );
}

/// Serialize secret key → deserialize → original pk encapsulates → decap works.
fn mlkem_sk_serialize_deserialize_roundtrip<P>()
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen must succeed");

    let sk_bytes = sk.to_bytes().to_vec();
    let sk2 = MlKemSecretKey::<P>::from_bytes(&sk_bytes).expect("sk from_bytes must succeed");
    assert_eq!(
        sk.to_bytes(),
        sk2.to_bytes(),
        "sk bytes must survive serialize→deserialize"
    );

    // Encapsulate to the original public key.
    let (ct, ss_send) = pk.encapsulate(&mut OsRng).expect("encap must succeed");

    // Decapsulate using the deserialized secret key.
    let ss_recv = sk2
        .decapsulate(&ct)
        .expect("decap with deserialized sk must succeed");
    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "shared secrets must match after sk serialize→deserialize cycle"
    );
}

/// Ciphertext bit-flip → ML-KEM implicit rejection (different shared secret, no error).
///
/// Per FIPS 203 §6.4, a tampered ciphertext causes decapsulation to return a
/// pseudorandom implicit-rejection value rather than an error. This test
/// verifies that behaviour is preserved by the lupine wrapper.
fn mlkem_ciphertext_tamper_implicit_rejection<P>()
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen must succeed");
    let (ct, ss_good) = pk.encapsulate(&mut OsRng).expect("encap must succeed");

    let mut ct_bytes = ct.to_bytes().to_vec();
    ct_bytes[0] ^= 0xFF; // flip first byte
    let ct_tampered = MlKemCiphertext::<P>::from_bytes(&ct_bytes);

    let ss_bad = sk
        .decapsulate(&ct_tampered)
        .expect("decap of tampered CT must succeed (implicit rejection per FIPS 203)");
    assert_ne!(
        ss_good.as_bytes(),
        ss_bad.as_bytes(),
        "tampered ciphertext must produce a different shared secret (implicit rejection)"
    );
}

/// Wrong key: a ciphertext encapsulated to key A cannot be decapsulated by key B.
fn mlkem_wrong_key_rejection<P>()
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (_sk_a, pk_a) = generate_keypair::<P>(&mut OsRng).expect("keygen A must succeed");
    let (sk_b, _pk_b) = generate_keypair::<P>(&mut OsRng).expect("keygen B must succeed");

    let (ct, ss_a) = pk_a
        .encapsulate(&mut OsRng)
        .expect("encap to pk_a must succeed");

    // sk_b decapsulates a ciphertext meant for pk_a — implicit rejection means
    // we get a different value, not an error.
    let ss_wrong = sk_b
        .decapsulate(&ct)
        .expect("decap with wrong key must not error (implicit rejection)");
    assert_ne!(
        ss_a.as_bytes(),
        ss_wrong.as_bytes(),
        "decapsulation with wrong key must yield a different shared secret"
    );
}

// ── ML-KEM test instantiations ────────────────────────────────────────────────

#[test]
fn mlkem512_basic_roundtrip() {
    mlkem_basic_roundtrip::<ml_kem::MlKem512>();
}

#[test]
fn mlkem768_basic_roundtrip() {
    mlkem_basic_roundtrip::<ml_kem::MlKem768>();
}

#[test]
fn mlkem1024_basic_roundtrip() {
    mlkem_basic_roundtrip::<ml_kem::MlKem1024>();
}

#[test]
fn mlkem512_pk_serialize_deserialize() {
    mlkem_pk_serialize_deserialize_roundtrip::<ml_kem::MlKem512>();
}

#[test]
fn mlkem768_pk_serialize_deserialize() {
    mlkem_pk_serialize_deserialize_roundtrip::<ml_kem::MlKem768>();
}

#[test]
fn mlkem1024_pk_serialize_deserialize() {
    mlkem_pk_serialize_deserialize_roundtrip::<ml_kem::MlKem1024>();
}

#[test]
fn mlkem512_sk_serialize_deserialize() {
    mlkem_sk_serialize_deserialize_roundtrip::<ml_kem::MlKem512>();
}

#[test]
fn mlkem768_sk_serialize_deserialize() {
    mlkem_sk_serialize_deserialize_roundtrip::<ml_kem::MlKem768>();
}

#[test]
fn mlkem1024_sk_serialize_deserialize() {
    mlkem_sk_serialize_deserialize_roundtrip::<ml_kem::MlKem1024>();
}

#[test]
fn mlkem512_tamper_implicit_rejection() {
    mlkem_ciphertext_tamper_implicit_rejection::<ml_kem::MlKem512>();
}

#[test]
fn mlkem768_tamper_implicit_rejection() {
    mlkem_ciphertext_tamper_implicit_rejection::<ml_kem::MlKem768>();
}

#[test]
fn mlkem1024_tamper_implicit_rejection() {
    mlkem_ciphertext_tamper_implicit_rejection::<ml_kem::MlKem1024>();
}

#[test]
fn mlkem512_wrong_key_rejection() {
    mlkem_wrong_key_rejection::<ml_kem::MlKem512>();
}

#[test]
fn mlkem768_wrong_key_rejection() {
    mlkem_wrong_key_rejection::<ml_kem::MlKem768>();
}

#[test]
fn mlkem1024_wrong_key_rejection() {
    mlkem_wrong_key_rejection::<ml_kem::MlKem1024>();
}

// ── Hybrid KEM roundtrip helpers ─────────────────────────────────────────────

/// Full hybrid roundtrip: keygen → encap → decap → combined secrets match.
fn hybrid_basic_roundtrip<P>()
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = hybrid::generate_keypair::<P>(&mut OsRng).expect("hybrid keygen must succeed");
    let (ct, ss_send) = pk
        .encapsulate(&mut OsRng)
        .expect("hybrid encap must succeed");
    let ss_recv = sk.decapsulate(&ct).expect("hybrid decap must succeed");
    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "hybrid shared secrets must match"
    );
    assert_eq!(
        ss_send.as_bytes().len(),
        32,
        "hybrid shared secret must be 32 bytes"
    );
}

/// Hybrid serialize→deserialize→re-use cycle.
///
/// Deserializes both the public and secret keys, sets the cached ML-KEM pk
/// bytes (required for decapsulation via KitchenSink), then runs a full
/// encap+decap cycle.
fn hybrid_serialize_deserialize_roundtrip<P>()
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = hybrid::generate_keypair::<P>(&mut OsRng).expect("hybrid keygen must succeed");

    // Serialize both keys.
    let pk_bytes = pk.to_bytes();
    let sk_bytes = sk.to_bytes();

    // Deserialize public key.
    let pk2 =
        HybridKemPublicKey::<P>::from_bytes(&pk_bytes).expect("hybrid pk from_bytes must succeed");
    assert_eq!(
        pk.to_bytes(),
        pk2.to_bytes(),
        "hybrid pk bytes must round-trip"
    );

    // Deserialize secret key — then restore the cached ML-KEM pk bytes.
    let mut sk2 =
        HybridKemSecretKey::<P>::from_bytes(&sk_bytes).expect("hybrid sk from_bytes must succeed");
    // pk_bytes[32..] is the ML-KEM public key portion (after the 32-byte X25519 pk).
    sk2.set_mlkem_pk_bytes(pk_bytes[32..].to_vec());

    // Encapsulate to deserialized pk.
    let (ct, ss_send) = pk2
        .encapsulate(&mut OsRng)
        .expect("encap to deserialized pk must succeed");

    // Decapsulate with deserialized sk.
    let ss_recv = sk2
        .decapsulate(&ct)
        .expect("decap with deserialized sk must succeed");
    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "hybrid shared secrets must match after serialize→deserialize"
    );
}

/// Hybrid tamper: flipping a byte in the ML-KEM ciphertext portion yields a
/// different combined shared secret (KitchenSink mixes all components).
fn hybrid_tamper_detection<P>()
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = hybrid::generate_keypair::<P>(&mut OsRng).expect("keygen must succeed");
    let (ct, ss_good) = pk.encapsulate(&mut OsRng).expect("encap must succeed");

    // Flip a byte in the ML-KEM portion (bytes 32+ in the hybrid ciphertext).
    let mut ct_bytes = ct.to_bytes();
    ct_bytes[32] ^= 0xFF;
    let ct_tampered = HybridKemCiphertext::<P>::from_bytes(&ct_bytes)
        .expect("hybrid ct from_bytes must succeed even for tampered bytes");

    let ss_bad = sk
        .decapsulate(&ct_tampered)
        .expect("hybrid decap of tampered CT must succeed");
    assert_ne!(
        ss_good.as_bytes(),
        ss_bad.as_bytes(),
        "tampered hybrid CT must yield a different combined shared secret"
    );
}

// ── Hybrid test instantiations ────────────────────────────────────────────────

#[test]
fn hybrid512_basic_roundtrip() {
    hybrid_basic_roundtrip::<ml_kem::MlKem512>();
}

#[test]
fn hybrid768_basic_roundtrip() {
    hybrid_basic_roundtrip::<ml_kem::MlKem768>();
}

#[test]
fn hybrid1024_basic_roundtrip() {
    hybrid_basic_roundtrip::<ml_kem::MlKem1024>();
}

#[test]
fn hybrid512_serialize_deserialize() {
    hybrid_serialize_deserialize_roundtrip::<ml_kem::MlKem512>();
}

#[test]
fn hybrid768_serialize_deserialize() {
    hybrid_serialize_deserialize_roundtrip::<ml_kem::MlKem768>();
}

#[test]
fn hybrid1024_serialize_deserialize() {
    hybrid_serialize_deserialize_roundtrip::<ml_kem::MlKem1024>();
}

#[test]
fn hybrid512_tamper_detection() {
    hybrid_tamper_detection::<ml_kem::MlKem512>();
}

#[test]
fn hybrid768_tamper_detection() {
    hybrid_tamper_detection::<ml_kem::MlKem768>();
}

#[test]
fn hybrid1024_tamper_detection() {
    hybrid_tamper_detection::<ml_kem::MlKem1024>();
}

// ── Structural invariants ─────────────────────────────────────────────────────

/// Key sizes must match FIPS 203 Table 2.
///
/// ML-KEM-512: ek=800B, dk=1632B, ct=768B
/// ML-KEM-768: ek=1184B, dk=2400B, ct=1088B
/// ML-KEM-1024: ek=1568B, dk=3168B, ct=1568B
#[test]
fn mlkem_key_sizes_match_fips203() {
    let (sk512, pk512) = generate_keypair::<ml_kem::MlKem512>(&mut OsRng).unwrap();
    assert_eq!(
        pk512.to_bytes().len(),
        800,
        "ML-KEM-512 ek must be 800 bytes"
    );
    assert_eq!(
        sk512.to_bytes().len(),
        1632,
        "ML-KEM-512 dk must be 1632 bytes"
    );

    let (sk768, pk768) = generate_keypair::<ml_kem::MlKem768>(&mut OsRng).unwrap();
    assert_eq!(
        pk768.to_bytes().len(),
        1184,
        "ML-KEM-768 ek must be 1184 bytes"
    );
    assert_eq!(
        sk768.to_bytes().len(),
        2400,
        "ML-KEM-768 dk must be 2400 bytes"
    );

    let (sk1024, pk1024) = generate_keypair::<ml_kem::MlKem1024>(&mut OsRng).unwrap();
    assert_eq!(
        pk1024.to_bytes().len(),
        1568,
        "ML-KEM-1024 ek must be 1568 bytes"
    );
    assert_eq!(
        sk1024.to_bytes().len(),
        3168,
        "ML-KEM-1024 dk must be 3168 bytes"
    );
}

/// Ciphertext sizes must match FIPS 203 Table 2.
#[test]
fn mlkem_ciphertext_sizes_match_fips203() {
    let (_, pk512) = generate_keypair::<ml_kem::MlKem512>(&mut OsRng).unwrap();
    let (ct512, _) = pk512.encapsulate(&mut OsRng).unwrap();
    assert_eq!(
        ct512.to_bytes().len(),
        768,
        "ML-KEM-512 ciphertext must be 768 bytes"
    );

    let (_, pk768) = generate_keypair::<ml_kem::MlKem768>(&mut OsRng).unwrap();
    let (ct768, _) = pk768.encapsulate(&mut OsRng).unwrap();
    assert_eq!(
        ct768.to_bytes().len(),
        1088,
        "ML-KEM-768 ciphertext must be 1088 bytes"
    );

    let (_, pk1024) = generate_keypair::<ml_kem::MlKem1024>(&mut OsRng).unwrap();
    let (ct1024, _) = pk1024.encapsulate(&mut OsRng).unwrap();
    assert_eq!(
        ct1024.to_bytes().len(),
        1568,
        "ML-KEM-1024 ciphertext must be 1568 bytes"
    );
}

/// Invalid key bytes: wrong-length slices must fail gracefully.
#[test]
fn invalid_key_bytes_are_rejected() {
    assert!(
        MlKemPublicKey::<ml_kem::MlKem768>::from_bytes(&[0u8; 4]).is_err(),
        "short bytes must be rejected"
    );
    assert!(
        MlKemSecretKey::<ml_kem::MlKem768>::from_bytes(&[0u8; 4]).is_err(),
        "short bytes must be rejected"
    );
    // Empty slice
    assert!(
        MlKemPublicKey::<ml_kem::MlKem512>::from_bytes(&[]).is_err(),
        "empty bytes must be rejected"
    );
}
