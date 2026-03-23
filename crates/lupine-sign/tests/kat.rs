//! Known-Answer Test (KAT) vectors for lupine-sign.
//!
//! These tests use a deterministic RNG seeded from a fixed 32-byte value to
//! generate keypairs and run signature operations, then compare output against
//! embedded hex-encoded golden values.
//!
//! ## Purpose
//!
//! The KAT vectors guard against silent regressions when upstream crates
//! (ml-dsa, slh-dsa, ed25519-dalek, rand, etc.) are updated. If the golden
//! values change, a dependency changed cryptographic behaviour — always
//! investigate before updating the golden constant.
//!
//! ## Algorithms tested
//!
//! - ML-DSA-44, ML-DSA-65, ML-DSA-87 (deterministic signing, so signatures
//!   are fully reproducible)
//! - SLH-DSA-SHA2-128s (deterministic, so reproducible; limited to one variant
//!   because keygen is slow)
//! - Hybrid Ed25519+ML-DSA-44 (deterministic signing for both components)
//!
//! ## Regenerating golden values
//!
//! Run: `cargo test -p lupine-sign --test kat print_kat_values -- --nocapture`
//! Capture the printed hex strings and update the constants below.
//!
//! @decision DEC-TEST-SIGN-001
//! @title StdRng::from_seed for deterministic KAT vectors in lupine-sign
//! @status accepted
//! @rationale lupine-sign uses rand 0.10 (RC). `rand::rngs::StdRng` (from
//!   rand 0.10's `std_rng` feature, available in the default feature set)
//!   implements `rand_core::CryptoRng` (rand_core 0.10) and accepts a fixed
//!   `[u8; 32]` seed via `SeedableRng::from_seed`. ML-DSA uses deterministic
//!   signing (`sign_deterministic`), so the same seed always produces the same
//!   signature — making golden-value comparison exact. SLH-DSA uses the
//!   `signature::Signer::try_sign` path (deterministic: opt_rand = pk_seed),
//!   so signatures are also reproducible.

use hex;
use lupine_sign::{hybrid_generate_keypair, ml_dsa_generate_keypair, slh_dsa_generate_keypair};
use ml_dsa::{KeyGen, MlDsaParams};
use rand::{rngs::StdRng, SeedableRng};
use slh_dsa::ParameterSet;

// ── KAT seeds ─────────────────────────────────────────────────────────────────

/// Fixed seed for key generation in all sign KAT tests.
const KAT_SEED: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// Test message used for all sign KAT operations.
const KAT_MESSAGE: &[u8] = b"lupine-sign KAT test message v1";

// ── Golden values — ML-DSA ────────────────────────────────────────────────────
// Captured via: cargo test -p lupine-sign --test kat print_kat_values -- --nocapture
// Upstream: ml-dsa 0.1.0-rc.7, rand 0.10.0, StdRng with KAT_SEED.

/// ML-DSA-44: first 16 bytes of the verifying key, hex-encoded.
const ML_DSA_44_VK_PREFIX: &str = "167cfd72f5a96194baf662a18302b2c0";
/// ML-DSA-44: first 32 bytes of the signature, hex-encoded.
const ML_DSA_44_SIG_PREFIX: &str =
    "a77c704f77377fba95d83a38762643d3883818bcc80d959be3fd876bc843255d";

/// ML-DSA-65: first 16 bytes of the verifying key, hex-encoded.
const ML_DSA_65_VK_PREFIX: &str = "4bea25f8c98c01e009ae87c6d800cb5d";
/// ML-DSA-65: first 32 bytes of the signature, hex-encoded.
const ML_DSA_65_SIG_PREFIX: &str =
    "5bf40c71665e0f530f09a367392bb3ae86b74d47e6329d9a30b3287e0527df72";

/// ML-DSA-87: first 16 bytes of the verifying key, hex-encoded.
const ML_DSA_87_VK_PREFIX: &str = "5319bddf75df4489dbf42cfa483ea8f6";
/// ML-DSA-87: first 32 bytes of the signature, hex-encoded.
const ML_DSA_87_SIG_PREFIX: &str =
    "14b325f0c49e2ddfdcf065790ee5d280c97f7435959a1275966f3a7b67155a9b";

/// SLH-DSA-SHA2-128s: first 16 bytes of the verifying key, hex-encoded.
const SLH_DSA_SHA2_128S_VK_PREFIX: &str = "c0135a77f267c6419c9bc9ebf41caaf7";

// ── Helper: run ML-DSA KAT ────────────────────────────────────────────────────

/// Run the deterministic KAT for a single ML-DSA parameter set.
///
/// Returns `(vk_prefix_hex, sig_prefix_hex)`.
/// Internally asserts that sign→verify succeeds.
fn run_mldsa_kat<P>() -> (String, String)
where
    P: KeyGen + MlDsaParams,
{
    let mut rng = StdRng::from_seed(KAT_SEED);
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("ML-DSA keygen must succeed");

    let vk_prefix = hex::encode(&vk.to_bytes()[..16]);

    let sig = sk.sign(KAT_MESSAGE).expect("ML-DSA sign must succeed");

    // Verify: must always succeed with the correct key.
    vk.verify(KAT_MESSAGE, &sig)
        .expect("ML-DSA verify must succeed");

    let sig_prefix = hex::encode(&sig.to_bytes()[..32]);

    (vk_prefix, sig_prefix)
}

/// Run the deterministic KAT for SLH-DSA (deterministic signing path).
fn run_slhdsa_kat<P: ParameterSet>() -> (String, String) {
    let mut rng = StdRng::from_seed(KAT_SEED);
    let (sk, vk) = slh_dsa_generate_keypair::<P>(&mut rng).expect("SLH-DSA keygen must succeed");

    let vk_prefix = hex::encode(&vk.to_bytes()[..16]);

    let sig = sk.sign(KAT_MESSAGE).expect("SLH-DSA sign must succeed");

    // Verify: must always succeed.
    vk.verify(KAT_MESSAGE, &sig)
        .expect("SLH-DSA verify must succeed");

    let sig_prefix = hex::encode(&sig.to_bytes()[..32]);

    (vk_prefix, sig_prefix)
}

/// Run the deterministic KAT for hybrid Ed25519+ML-DSA.
fn run_hybrid_kat<P>() -> (String, String)
where
    P: KeyGen + MlDsaParams,
{
    let mut rng = StdRng::from_seed(KAT_SEED);
    let (sk, vk) = hybrid_generate_keypair::<P>(&mut rng).expect("hybrid keygen must succeed");

    // Hybrid vk: 32 bytes Ed25519 || ML-DSA vk bytes.
    let vk_bytes = vk.to_bytes();
    let vk_prefix = hex::encode(&vk_bytes[..16]);

    let sig = sk.sign(KAT_MESSAGE).expect("hybrid sign must succeed");
    vk.verify(KAT_MESSAGE, &sig)
        .expect("hybrid verify must succeed");

    let sig_bytes = sig.to_bytes();
    // sig is length-prefixed: [4 bytes len][64 bytes ed25519][4 bytes len][mldsa sig]
    // prefix from byte 4 (after the ed25519 length prefix).
    let sig_prefix = hex::encode(&sig_bytes[4..36]); // 32 bytes of ed25519 sig

    (vk_prefix, sig_prefix)
}

// ── Diagnostic: print fresh golden values ─────────────────────────────────────

/// Diagnostic test: prints current golden values to stderr.
///
/// Run with `-- --nocapture` to see the output. Use to regenerate constants
/// after an intentional upstream version bump.
///
/// Note: ML-DSA-87 requires a large stack.
#[test]
fn print_kat_values() {
    let (vk44, sig44) = run_mldsa_kat::<ml_dsa::MlDsa44>();
    let (vk65, sig65) = run_mldsa_kat::<ml_dsa::MlDsa65>();

    // ML-DSA-87 needs a larger stack in debug builds.
    let (vk87, sig87) = {
        let result = std::sync::Arc::new(std::sync::Mutex::new((String::new(), String::new())));
        let result_clone = result.clone();
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(move || {
                let vals = run_mldsa_kat::<ml_dsa::MlDsa87>();
                *result_clone.lock().unwrap() = vals;
            })
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
        let guard = result.lock().unwrap();
        (guard.0.clone(), guard.1.clone())
    };

    let (vk_slh, sig_slh) = run_slhdsa_kat::<slh_dsa::Sha2_128s>();
    let (vk_h44, sig_h44) = run_hybrid_kat::<ml_dsa::MlDsa44>();

    eprintln!("=== lupine-sign KAT golden values ===");
    eprintln!("ML_DSA_44_VK_PREFIX:          {vk44}");
    eprintln!("ML_DSA_44_SIG_PREFIX:         {sig44}");
    eprintln!("ML_DSA_65_VK_PREFIX:          {vk65}");
    eprintln!("ML_DSA_65_SIG_PREFIX:         {sig65}");
    eprintln!("ML_DSA_87_VK_PREFIX:          {vk87}");
    eprintln!("ML_DSA_87_SIG_PREFIX:         {sig87}");
    eprintln!("SLH_DSA_SHA2_128S_VK_PREFIX:  {vk_slh}");
    eprintln!("SLH_DSA_SHA2_128S_SIG_PREFIX: {sig_slh}");
    eprintln!("HYBRID_44_VK_PREFIX:          {vk_h44}");
    eprintln!("HYBRID_44_SIG_PREFIX (ed25519 part): {sig_h44}");
}

// ── ML-DSA golden-value regression tests ──────────────────────────────────────

/// Regression: ML-DSA-44 vk and signature prefix must match golden values.
#[test]
fn kat_mldsa_44_golden() {
    let (vk_prefix, sig_prefix) = run_mldsa_kat::<ml_dsa::MlDsa44>();
    assert_eq!(
        vk_prefix, ML_DSA_44_VK_PREFIX,
        "ML-DSA-44 vk prefix regression"
    );
    assert_eq!(
        sig_prefix, ML_DSA_44_SIG_PREFIX,
        "ML-DSA-44 sig prefix regression"
    );
}

/// Regression: ML-DSA-65 vk and signature prefix must match golden values.
#[test]
fn kat_mldsa_65_golden() {
    let (vk_prefix, sig_prefix) = run_mldsa_kat::<ml_dsa::MlDsa65>();
    assert_eq!(
        vk_prefix, ML_DSA_65_VK_PREFIX,
        "ML-DSA-65 vk prefix regression"
    );
    assert_eq!(
        sig_prefix, ML_DSA_65_SIG_PREFIX,
        "ML-DSA-65 sig prefix regression"
    );
}

/// Regression: ML-DSA-87 must match golden values.
///
/// Uses a large stack thread because debug-mode ML-DSA-87 has large stack intermediates.
#[test]
fn kat_mldsa_87_golden() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (vk_prefix, sig_prefix) = run_mldsa_kat::<ml_dsa::MlDsa87>();
            assert_eq!(
                vk_prefix, ML_DSA_87_VK_PREFIX,
                "ML-DSA-87 vk prefix regression"
            );
            assert_eq!(
                sig_prefix, ML_DSA_87_SIG_PREFIX,
                "ML-DSA-87 sig prefix regression"
            );
        })
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// ── ML-DSA determinism tests ──────────────────────────────────────────────────

/// Determinism: same seed always produces identical ML-DSA-44 output.
#[test]
fn kat_mldsa_44_deterministic() {
    let (vk1, sig1) = run_mldsa_kat::<ml_dsa::MlDsa44>();
    let (vk2, sig2) = run_mldsa_kat::<ml_dsa::MlDsa44>();
    assert_eq!(vk1, vk2, "ML-DSA-44 vk must be deterministic");
    assert_eq!(sig1, sig2, "ML-DSA-44 sig must be deterministic");
}

/// Determinism: same seed always produces identical ML-DSA-65 output.
#[test]
fn kat_mldsa_65_deterministic() {
    let (vk1, sig1) = run_mldsa_kat::<ml_dsa::MlDsa65>();
    let (vk2, sig2) = run_mldsa_kat::<ml_dsa::MlDsa65>();
    assert_eq!(vk1, vk2);
    assert_eq!(sig1, sig2);
}

// ── SLH-DSA KAT tests ─────────────────────────────────────────────────────────

/// Regression: SLH-DSA-SHA2-128s vk prefix must match golden value.
///
/// Signing is deterministic (opt_rand = pk_seed) so the signature is reproducible.
#[test]
fn kat_slhdsa_sha2_128s_golden() {
    let (vk_prefix, _sig_prefix) = run_slhdsa_kat::<slh_dsa::Sha2_128s>();
    assert_eq!(
        vk_prefix, SLH_DSA_SHA2_128S_VK_PREFIX,
        "SLH-DSA-SHA2-128s vk prefix regression"
    );
}

/// Determinism: SLH-DSA-SHA2-128s produces identical output for same seed.
#[test]
fn kat_slhdsa_sha2_128s_deterministic() {
    let (vk1, sig1) = run_slhdsa_kat::<slh_dsa::Sha2_128s>();
    let (vk2, sig2) = run_slhdsa_kat::<slh_dsa::Sha2_128s>();
    assert_eq!(vk1, vk2, "SLH-DSA-SHA2-128s vk must be deterministic");
    assert_eq!(sig1, sig2, "SLH-DSA-SHA2-128s sig must be deterministic");
}

// ── Hybrid KAT tests ──────────────────────────────────────────────────────────

/// Determinism: Hybrid Ed25519+ML-DSA-44 produces identical output for same seed.
#[test]
fn kat_hybrid_44_deterministic() {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let (vk1, sig1) = run_hybrid_kat::<ml_dsa::MlDsa44>();
            let (vk2, sig2) = run_hybrid_kat::<ml_dsa::MlDsa44>();
            assert_eq!(vk1, vk2, "Hybrid-44 vk must be deterministic");
            assert_eq!(sig1, sig2, "Hybrid-44 sig must be deterministic");
        })
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// ── Cross-parameter regression guard ──────────────────────────────────────────

/// Cross-parameter: same seed produces different vk prefixes for different param sets.
///
/// Guards against a regression where different parameter set types accidentally
/// produce identical output.
#[test]
fn kat_different_param_sets_produce_different_vks() {
    assert_ne!(
        ML_DSA_44_VK_PREFIX, ML_DSA_65_VK_PREFIX,
        "ML-DSA-44 and ML-DSA-65 must produce different vk prefixes"
    );
    assert_ne!(
        ML_DSA_65_VK_PREFIX, ML_DSA_87_VK_PREFIX,
        "ML-DSA-65 and ML-DSA-87 must produce different vk prefixes"
    );
}

/// Cross-parameter: same seed produces different signature prefixes for different param sets.
///
/// Each ML-DSA parameter set has different internal structure and encoding,
/// so even with the same 32-byte seed the signatures differ across param sets.
#[test]
fn kat_different_param_sets_produce_different_sigs() {
    assert_ne!(
        ML_DSA_44_SIG_PREFIX, ML_DSA_65_SIG_PREFIX,
        "ML-DSA-44 and ML-DSA-65 must produce different sig prefixes"
    );
    assert_ne!(
        ML_DSA_65_SIG_PREFIX, ML_DSA_87_SIG_PREFIX,
        "ML-DSA-65 and ML-DSA-87 must produce different sig prefixes"
    );
}
