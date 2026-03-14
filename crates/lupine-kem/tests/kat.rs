//! Known-Answer Test (KAT) vectors for lupine-kem.
//!
//! These tests use a deterministic RNG seeded from a fixed 32-byte value to
//! generate keypairs and run KEM operations, then compare output against
//! embedded hex-encoded golden values.
//!
//! ## Purpose
//!
//! The KAT vectors guard against silent regressions when upstream crates
//! (ml-kem, rand, etc.) are updated. If the golden values change, a dependency
//! changed behaviour — that is always worth investigating.
//!
//! ## Regenerating golden values
//!
//! Run: `cargo test -p lupine-kem --test kat print_kat_values -- --nocapture`
//! Capture the printed hex strings and update the constants below.
//! Only do this when intentionally bumping an upstream crate version.
//!
//! @decision DEC-TEST-KEM-001
//! @title Deterministic RNG via StdRng::from_seed for KAT tests
//! @status accepted
//! @rationale lupine-kem's generate_keypair requires a `CryptoRngCore`
//!   (rand_core 0.6). `rand::rngs::StdRng` implements that trait and accepts
//!   a fixed `[u8; 32]` seed via `SeedableRng::from_seed`, making test vectors
//!   fully reproducible without any additional crate dependencies. Using
//!   OS-level randomness (OsRng) in KAT tests would make the vectors
//!   non-reproducible and defeat the regression-detection purpose.
//!   Golden values are captured from the first deterministic run and embedded
//!   as constants — any change triggers a test failure requiring explicit review.

use hex;
use lupine_kem::{
    generate_keypair,
    hybrid,
};
use ml_kem::{EncodedSizeUser, KemCore, kem::{Decapsulate, Encapsulate}};
use rand::SeedableRng;
use rand::rngs::StdRng;

// ── KAT seeds ────────────────────────────────────────────────────────────────

/// Fixed seed for key generation in all KAT tests.
const KAT_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Separate seed for the encapsulation RNG (keygen and encap must use independent RNGs).
const ENCAP_SEED: [u8; 32] = [
    0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
    0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
    0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
    0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0,
];

// ── Golden values — ML-KEM ────────────────────────────────────────────────────
// Captured via: cargo test -p lupine-kem --test kat print_kat_values -- --nocapture
// Upstream: ml-kem 0.2, rand 0.8.5, StdRng with KAT_SEED / ENCAP_SEED.

/// ML-KEM-512: first 16 bytes of the encapsulation key, hex-encoded.
const ML_KEM_512_PK_PREFIX: &str = "5c660a9552b8eef5b41fb42541592617";
/// ML-KEM-512: 32-byte shared secret (hex) from KAT keygen + encap + decap.
const ML_KEM_512_SS: &str = "57df0ca26c855d4072f0901c1a5d7394be48c8fdb3be958ff72fc067a26a80b6";

/// ML-KEM-768: first 16 bytes of the encapsulation key, hex-encoded.
const ML_KEM_768_PK_PREFIX: &str = "43921c2c61a242204f40ec57ca42cb5d";
/// ML-KEM-768: 32-byte shared secret (hex) from KAT keygen + encap + decap.
const ML_KEM_768_SS: &str = "09d46666d159706c10283a0b424b00937773ab64cf44c0d82da925e626580646";

/// ML-KEM-1024: first 16 bytes of the encapsulation key, hex-encoded.
const ML_KEM_1024_PK_PREFIX: &str = "bff51e07b44dcb4698cf8cbc7fbb33a6";
/// ML-KEM-1024: 32-byte shared secret (hex) from KAT keygen + encap + decap.
const ML_KEM_1024_SS: &str = "2984a2ef260aad1726572fdafcfc035f8532f75755452d98ade07e4855d721c8";

// ── Helper: run KAT for one ML-KEM parameter set ─────────────────────────────

/// Run the deterministic KAT for a single ML-KEM parameter set.
///
/// Returns `(pk_prefix_hex, shared_secret_hex)`.
/// Internally asserts that encap and decap produce the same shared secret.
fn run_mlkem_kat<P>() -> (String, String)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser
        + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let mut rng_keygen = StdRng::from_seed(KAT_SEED);
    let (sk, pk) = generate_keypair::<P>(&mut rng_keygen).expect("keygen must succeed");

    let pk_bytes = pk.to_bytes();
    let pk_prefix = hex::encode(&pk_bytes[..16]);

    let mut rng_encap = StdRng::from_seed(ENCAP_SEED);
    let (ct, ss_send) = pk.encapsulate(&mut rng_encap).expect("encap must succeed");
    let ss_recv = sk.decapsulate(&ct).expect("decap must succeed");

    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "KAT: encap and decap shared secrets must match"
    );

    (pk_prefix, hex::encode(ss_send.as_bytes()))
}

/// Run the deterministic KAT for a hybrid X25519+ML-KEM parameter set.
fn run_hybrid_kat<P>() -> (String, String)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser
        + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::EncapsulationKey: EncodedSizeUser
        + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let mut rng_keygen = StdRng::from_seed(KAT_SEED);
    let (sk, pk) = hybrid::generate_keypair::<P>(&mut rng_keygen)
        .expect("hybrid keygen must succeed");

    let pk_bytes = pk.to_bytes();
    let pk_prefix = hex::encode(&pk_bytes[..16]);

    let mut rng_encap = StdRng::from_seed(ENCAP_SEED);
    let (ct, ss_send) = pk.encapsulate(&mut rng_encap).expect("hybrid encap must succeed");
    let ss_recv = sk.decapsulate(&ct).expect("hybrid decap must succeed");

    assert_eq!(
        ss_send.as_bytes(),
        ss_recv.as_bytes(),
        "Hybrid KAT: encap and decap shared secrets must match"
    );

    (pk_prefix, hex::encode(ss_send.as_bytes()))
}

// ── Utility: print fresh golden values ───────────────────────────────────────

/// Diagnostic test: prints current golden values to stderr.
///
/// Run with `-- --nocapture` to see the output. Use this to regenerate
/// constants after an intentional upstream version bump.
#[test]
fn print_kat_values() {
    let (pk512, ss512) = run_mlkem_kat::<ml_kem::MlKem512>();
    let (pk768, ss768) = run_mlkem_kat::<ml_kem::MlKem768>();
    let (pk1024, ss1024) = run_mlkem_kat::<ml_kem::MlKem1024>();
    let (hpk512, hss512) = run_hybrid_kat::<ml_kem::MlKem512>();
    let (hpk768, hss768) = run_hybrid_kat::<ml_kem::MlKem768>();
    let (hpk1024, hss1024) = run_hybrid_kat::<ml_kem::MlKem1024>();

    eprintln!("=== ML-KEM KAT golden values ===");
    eprintln!("ML_KEM_512_PK_PREFIX:   {pk512}");
    eprintln!("ML_KEM_512_SS:          {ss512}");
    eprintln!("ML_KEM_768_PK_PREFIX:   {pk768}");
    eprintln!("ML_KEM_768_SS:          {ss768}");
    eprintln!("ML_KEM_1024_PK_PREFIX:  {pk1024}");
    eprintln!("ML_KEM_1024_SS:         {ss1024}");
    eprintln!("=== Hybrid KEM KAT golden values ===");
    eprintln!("HYBRID_512_PK_PREFIX:   {hpk512}");
    eprintln!("HYBRID_512_SS:          {hss512}");
    eprintln!("HYBRID_768_PK_PREFIX:   {hpk768}");
    eprintln!("HYBRID_768_SS:          {hss768}");
    eprintln!("HYBRID_1024_PK_PREFIX:  {hpk1024}");
    eprintln!("HYBRID_1024_SS:         {hss1024}");
}

// ── ML-KEM golden-value regression tests ─────────────────────────────────────

/// Regression: ML-KEM-512 keygen and shared secret must match golden values.
///
/// Failure means an upstream crate changed cryptographic output — investigate
/// before updating the golden constant.
#[test]
fn kat_mlkem_512_golden() {
    let (pk_prefix, ss_hex) = run_mlkem_kat::<ml_kem::MlKem512>();
    assert_eq!(pk_prefix, ML_KEM_512_PK_PREFIX, "ML-KEM-512 public key prefix regression");
    assert_eq!(ss_hex, ML_KEM_512_SS, "ML-KEM-512 shared secret regression");
}

/// Regression: ML-KEM-768 keygen and shared secret must match golden values.
#[test]
fn kat_mlkem_768_golden() {
    let (pk_prefix, ss_hex) = run_mlkem_kat::<ml_kem::MlKem768>();
    assert_eq!(pk_prefix, ML_KEM_768_PK_PREFIX, "ML-KEM-768 public key prefix regression");
    assert_eq!(ss_hex, ML_KEM_768_SS, "ML-KEM-768 shared secret regression");
}

/// Regression: ML-KEM-1024 keygen and shared secret must match golden values.
#[test]
fn kat_mlkem_1024_golden() {
    let (pk_prefix, ss_hex) = run_mlkem_kat::<ml_kem::MlKem1024>();
    assert_eq!(pk_prefix, ML_KEM_1024_PK_PREFIX, "ML-KEM-1024 public key prefix regression");
    assert_eq!(ss_hex, ML_KEM_1024_SS, "ML-KEM-1024 shared secret regression");
}

// ── Determinism tests ─────────────────────────────────────────────────────────

/// Determinism: same seed always produces identical output for ML-KEM-512.
#[test]
fn kat_mlkem_512_deterministic() {
    let (pk1, ss1) = run_mlkem_kat::<ml_kem::MlKem512>();
    let (pk2, ss2) = run_mlkem_kat::<ml_kem::MlKem512>();
    assert_eq!(pk1, pk2, "ML-KEM-512 keygen must be deterministic");
    assert_eq!(ss1, ss2, "ML-KEM-512 shared secret must be deterministic");
}

/// Determinism: same seed always produces identical output for ML-KEM-768.
#[test]
fn kat_mlkem_768_deterministic() {
    let (pk1, ss1) = run_mlkem_kat::<ml_kem::MlKem768>();
    let (pk2, ss2) = run_mlkem_kat::<ml_kem::MlKem768>();
    assert_eq!(pk1, pk2);
    assert_eq!(ss1, ss2);
}

/// Determinism: same seed always produces identical output for ML-KEM-1024.
#[test]
fn kat_mlkem_1024_deterministic() {
    let (pk1, ss1) = run_mlkem_kat::<ml_kem::MlKem1024>();
    let (pk2, ss2) = run_mlkem_kat::<ml_kem::MlKem1024>();
    assert_eq!(pk1, pk2);
    assert_eq!(ss1, ss2);
}

// ── Hybrid KAT determinism ────────────────────────────────────────────────────

#[test]
fn kat_hybrid_512_deterministic() {
    let (pk1, ss1) = run_hybrid_kat::<ml_kem::MlKem512>();
    let (pk2, ss2) = run_hybrid_kat::<ml_kem::MlKem512>();
    assert_eq!(pk1, pk2, "Hybrid-512 keygen must be deterministic");
    assert_eq!(ss1, ss2, "Hybrid-512 shared secret must be deterministic");
}

#[test]
fn kat_hybrid_768_deterministic() {
    let (pk1, ss1) = run_hybrid_kat::<ml_kem::MlKem768>();
    let (pk2, ss2) = run_hybrid_kat::<ml_kem::MlKem768>();
    assert_eq!(pk1, pk2);
    assert_eq!(ss1, ss2);
}

#[test]
fn kat_hybrid_1024_deterministic() {
    let (pk1, ss1) = run_hybrid_kat::<ml_kem::MlKem1024>();
    let (pk2, ss2) = run_hybrid_kat::<ml_kem::MlKem1024>();
    assert_eq!(pk1, pk2);
    assert_eq!(ss1, ss2);
}

/// Structural: shared secrets are always exactly 32 bytes (= 64 hex chars).
#[test]
fn kat_shared_secret_length_is_32_bytes() {
    for ss in [ML_KEM_512_SS, ML_KEM_768_SS, ML_KEM_1024_SS] {
        assert_eq!(ss.len(), 64, "shared secret must be 32 bytes (64 hex chars)");
    }
}

/// Cross-parameter: same seed produces different public keys for different param sets.
///
/// This guards against a regression where the generic parameter is collapsed and
/// different param sets accidentally produce the same output.
#[test]
fn kat_different_param_sets_produce_different_keys() {
    assert_ne!(
        ML_KEM_512_PK_PREFIX, ML_KEM_768_PK_PREFIX,
        "ML-KEM-512 and ML-KEM-768 must produce different public keys from the same seed"
    );
    assert_ne!(
        ML_KEM_768_PK_PREFIX, ML_KEM_1024_PK_PREFIX,
        "ML-KEM-768 and ML-KEM-1024 must produce different public keys from the same seed"
    );
    assert_ne!(
        ML_KEM_512_SS, ML_KEM_768_SS,
        "ML-KEM-512 and ML-KEM-768 must produce different shared secrets"
    );
}
