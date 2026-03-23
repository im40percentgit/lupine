//! Property-based tests for lupine-sign using proptest.
//!
//! These tests verify cryptographic invariants hold across a wide range of
//! randomly generated messages:
//!
//! - **Sign/verify roundtrip**: for any message up to 1 KB, sign→verify succeeds.
//! - **Wrong key always rejects**: a signature from key A never verifies with key B.
//! - **Message mutation always fails**: any single-byte change to the message
//!   causes verify to fail.
//!
//! ## Case counts
//!
//! ML-DSA tests: 20 cases (fast signing, ~0.5s total per test).
//! Hybrid tests: 10 cases (Ed25519+ML-DSA, slightly more expensive).
//! SLH-DSA tests: 3 cases (slow signing, ~3s per case in debug builds).
//!
//! @decision DEC-TEST-SIGN-003
//! @title Proptest case counts: 20 for ML-DSA, 10 for hybrid, 3 for SLH-DSA
//! @status accepted
//! @rationale ML-DSA signing in debug builds takes ~10ms per operation. 20
//!   cases provides reasonable property coverage in ~0.5s. SLH-DSA-SHA2-128s
//!   signing takes ~300ms in debug builds; 3 cases provides basic coverage
//!   without making the test suite prohibitively slow. The slow test is gated
//!   with a comment so future engineers can increase the count with an
//!   `--ignored` flag or in release mode. Hybrid tests at 10 cases balance
//!   coverage with the combined cost of two signature operations per case.

use lupine_sign::{hybrid_generate_keypair, ml_dsa_generate_keypair, slh_dsa_generate_keypair};
use ml_dsa::{KeyGen, MlDsaParams};
use proptest::prelude::*;
use slh_dsa::ParameterSet;

// ── Large-stack helper ────────────────────────────────────────────────────────

/// Run `f` on a thread with 32 MB stack for ML-DSA-87/hybrid-87 debug builds.
fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new()
        .stack_size(32 * 1024 * 1024)
        .spawn(f)
        .expect("thread spawn failed")
        .join()
        .expect("thread panicked");
}

// ── ML-DSA property helpers ───────────────────────────────────────────────────

/// Property: sign→verify succeeds for any message.
fn prop_mldsa_sign_verify_roundtrip<P: KeyGen + MlDsaParams>(message: &[u8]) {
    let mut rng = rand::rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let sig = sk.sign(message).expect("sign must succeed");
    vk.verify(message, &sig).expect("verify must succeed");
}

/// Property: signature from key A never verifies with key B.
fn prop_mldsa_wrong_key_always_rejects<P: KeyGen + MlDsaParams>(message: &[u8]) {
    let mut rng = rand::rng();
    let (sk_a, _vk_a) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen A must succeed");
    let (_sk_b, vk_b) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen B must succeed");
    let sig = sk_a.sign(message).expect("sign must succeed");
    assert!(
        vk_b.verify(message, &sig).is_err(),
        "sig from key A must not verify with key B for any message"
    );
}

/// Property: mutating any byte of the message causes verify to fail.
fn prop_mldsa_message_mutation_fails<P: KeyGen + MlDsaParams>(
    message: Vec<u8>,
    mutation_idx: usize,
) {
    if message.is_empty() {
        return; // empty message can't be mutated
    }
    let mut rng = rand::rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let sig = sk.sign(&message).expect("sign must succeed");

    let mut mutated = message.clone();
    let idx = mutation_idx % mutated.len();
    mutated[idx] ^= 0xFF;

    assert!(
        vk.verify(&mutated, &sig).is_err(),
        "verify must fail after message mutation"
    );
}

// ── ML-DSA-44 property tests ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_mldsa44_sign_verify(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
        prop_mldsa_sign_verify_roundtrip::<ml_dsa::MlDsa44>(&msg);
    }

    #[test]
    fn prop_mldsa44_wrong_key_rejects(msg in prop::collection::vec(any::<u8>(), 1..512)) {
        prop_mldsa_wrong_key_always_rejects::<ml_dsa::MlDsa44>(&msg);
    }

    #[test]
    fn prop_mldsa44_message_mutation_fails(
        msg in prop::collection::vec(any::<u8>(), 1..256),
        idx in 0usize..256usize
    ) {
        prop_mldsa_message_mutation_fails::<ml_dsa::MlDsa44>(msg, idx);
    }
}

// ── ML-DSA-65 property tests ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_mldsa65_sign_verify(msg in prop::collection::vec(any::<u8>(), 0..1024)) {
        prop_mldsa_sign_verify_roundtrip::<ml_dsa::MlDsa65>(&msg);
    }

    #[test]
    fn prop_mldsa65_wrong_key_rejects(msg in prop::collection::vec(any::<u8>(), 1..512)) {
        prop_mldsa_wrong_key_always_rejects::<ml_dsa::MlDsa65>(&msg);
    }

    #[test]
    fn prop_mldsa65_message_mutation_fails(
        msg in prop::collection::vec(any::<u8>(), 1..256),
        idx in 0usize..256usize
    ) {
        prop_mldsa_message_mutation_fails::<ml_dsa::MlDsa65>(msg, idx);
    }
}

// ── ML-DSA-87 property tests (large stack) ────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(20))]

    #[test]
    fn prop_mldsa87_sign_verify(msg in prop::collection::vec(any::<u8>(), 0..512)) {
        with_large_stack(move || {
            prop_mldsa_sign_verify_roundtrip::<ml_dsa::MlDsa87>(&msg);
        });
    }

    #[test]
    fn prop_mldsa87_wrong_key_rejects(msg in prop::collection::vec(any::<u8>(), 1..256)) {
        with_large_stack(move || {
            prop_mldsa_wrong_key_always_rejects::<ml_dsa::MlDsa87>(&msg);
        });
    }
}

// ── SLH-DSA property helpers ──────────────────────────────────────────────────

fn prop_slhdsa_sign_verify<P: ParameterSet>(message: &[u8]) {
    let mut rng = rand::rng();
    let (sk, vk) = slh_dsa_generate_keypair::<P>(&mut rng).expect("SLH-DSA keygen must succeed");
    let sig = sk.sign(message).expect("SLH-DSA sign must succeed");
    vk.verify(message, &sig)
        .expect("SLH-DSA verify must succeed");
}

fn prop_slhdsa_message_mutation_fails<P: ParameterSet>(message: Vec<u8>, mutation_idx: usize) {
    if message.is_empty() {
        return;
    }
    let mut rng = rand::rng();
    let (sk, vk) = slh_dsa_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let sig = sk.sign(&message).expect("sign must succeed");

    let mut mutated = message.clone();
    let idx = mutation_idx % mutated.len();
    mutated[idx] ^= 0xFF;

    assert!(
        vk.verify(&mutated, &sig).is_err(),
        "SLH-DSA verify must fail after message mutation"
    );
}

// ── SLH-DSA-SHA2-128s property tests (3 cases — slow) ────────────────────────

proptest! {
    // 3 cases because SLH-DSA-SHA2-128s signing takes ~300ms in debug builds.
    // Increase to 10+ cases in release mode or when running slow tests explicitly.
    #![proptest_config(ProptestConfig::with_cases(3))]

    #[test]
    fn prop_slhdsa_sha2_128s_sign_verify(msg in prop::collection::vec(any::<u8>(), 0..64)) {
        prop_slhdsa_sign_verify::<slh_dsa::Sha2_128s>(&msg);
    }

    #[test]
    fn prop_slhdsa_sha2_128s_message_mutation_fails(
        msg in prop::collection::vec(any::<u8>(), 1..32),
        idx in 0usize..32usize
    ) {
        prop_slhdsa_message_mutation_fails::<slh_dsa::Sha2_128s>(msg, idx);
    }
}

// ── Hybrid Ed25519+ML-DSA property helpers ────────────────────────────────────

fn prop_hybrid_sign_verify<P: KeyGen + MlDsaParams>(message: &[u8]) {
    let mut rng = rand::rng();
    let (sk, vk) = hybrid_generate_keypair::<P>(&mut rng).expect("hybrid keygen must succeed");
    let sig = sk.sign(message).expect("hybrid sign must succeed");
    vk.verify(message, &sig)
        .expect("hybrid verify must succeed");
}

fn prop_hybrid_wrong_key_rejects<P: KeyGen + MlDsaParams>(message: &[u8]) {
    let mut rng = rand::rng();
    let (sk_a, _vk_a) = hybrid_generate_keypair::<P>(&mut rng).expect("keygen A must succeed");
    let (_sk_b, vk_b) = hybrid_generate_keypair::<P>(&mut rng).expect("keygen B must succeed");
    let sig = sk_a.sign(message).expect("sign must succeed");
    assert!(
        vk_b.verify(message, &sig).is_err(),
        "hybrid sig from key A must not verify with key B"
    );
}

fn prop_hybrid_message_mutation_fails<P: KeyGen + MlDsaParams>(
    message: Vec<u8>,
    mutation_idx: usize,
) {
    if message.is_empty() {
        return;
    }
    let mut rng = rand::rng();
    let (sk, vk) = hybrid_generate_keypair::<P>(&mut rng).expect("keygen must succeed");
    let sig = sk.sign(&message).expect("sign must succeed");

    let mut mutated = message.clone();
    let idx = mutation_idx % mutated.len();
    mutated[idx] ^= 0xFF;

    assert!(
        vk.verify(&mutated, &sig).is_err(),
        "hybrid verify must fail after message mutation"
    );
}

// ── Hybrid-44 property tests ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_hybrid44_sign_verify(msg in prop::collection::vec(any::<u8>(), 0..512)) {
        with_large_stack(move || {
            prop_hybrid_sign_verify::<ml_dsa::MlDsa44>(&msg);
        });
    }

    #[test]
    fn prop_hybrid44_wrong_key_rejects(msg in prop::collection::vec(any::<u8>(), 1..256)) {
        with_large_stack(move || {
            prop_hybrid_wrong_key_rejects::<ml_dsa::MlDsa44>(&msg);
        });
    }

    #[test]
    fn prop_hybrid44_message_mutation_fails(
        msg in prop::collection::vec(any::<u8>(), 1..128),
        idx in 0usize..128usize
    ) {
        with_large_stack(move || {
            prop_hybrid_message_mutation_fails::<ml_dsa::MlDsa44>(msg, idx);
        });
    }
}

// ── Hybrid-65 property tests ──────────────────────────────────────────────────

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10))]

    #[test]
    fn prop_hybrid65_sign_verify(msg in prop::collection::vec(any::<u8>(), 0..512)) {
        with_large_stack(move || {
            prop_hybrid_sign_verify::<ml_dsa::MlDsa65>(&msg);
        });
    }

    #[test]
    fn prop_hybrid65_wrong_key_rejects(msg in prop::collection::vec(any::<u8>(), 1..256)) {
        with_large_stack(move || {
            prop_hybrid_wrong_key_rejects::<ml_dsa::MlDsa65>(&msg);
        });
    }
}
