//! Criterion benchmarks for lupine-sign.
//!
//! Measures keygen, sign, and verify for:
//! - ML-DSA (FIPS 204): parameter sets 44, 65, 87
//! - Hybrid Ed25519+ML-DSA: parameter sets 44, 65, 87
//! - SLH-DSA (FIPS 205): Sha2-128s, Sha2-128f, Sha2-256s (3 representative
//!   variants covering fast-vs-small and level-1-vs-5 trade-offs)
//!
//! # Running
//!
//! ```
//! cargo bench -p lupine-sign
//! ```
//!
//! # Notes on SLH-DSA timing
//!
//! SLH-DSA signing is substantially slower than ML-DSA (milliseconds vs.
//! microseconds). The `s` (small) variants are slower to sign but produce
//! smaller signatures; the `f` (fast) variants sign faster but produce
//! larger signatures. Criterion is configured with reduced `sample_size` and
//! extended `measurement_time` for SLH-DSA to produce stable estimates
//! without requiring hours of wallclock time.
//!
//! @decision DEC-BENCH-SIGN-001
//! @title Separate Criterion groups per algorithm family
//! @status accepted
//! @rationale ML-DSA, Hybrid-Sign, and SLH-DSA have vastly different timing
//!   profiles (μs vs ms). Separate groups let criterion auto-scale each plot's
//!   Y-axis so all three families are readable. If combined into one group,
//!   SLH-DSA bars would dwarf ML-DSA bars and make intra-family comparison
//!   impossible to read.
//!
//! @decision DEC-BENCH-SIGN-002
//! @title SLH-DSA benchmarks: 3 of 12 parameter sets
//! @status accepted
//! @rationale All 12 SLH-DSA parameter sets would take hours to benchmark
//!   exhaustively. We select 3 that cover the most important trade-off axes:
//!   Sha2-128s (level 1, small, reference baseline), Sha2-128f (level 1,
//!   fast — same level as 128s but faster signing), and Sha2-256s (level 5,
//!   small — shows scaling to the highest security level). The SHAKE variants
//!   at the same parameter size differ only in hash family and add negligible
//!   additional information for algorithm selection decisions.

use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ml_dsa::{KeyGen, MlDsaParams};
use slh_dsa::ParameterSet;

use lupine_sign::{hybrid_generate_keypair, ml_dsa_generate_keypair, slh_dsa_generate_keypair};

/// Message used for all sign/verify benchmarks — 64 bytes, representative of
/// a typical digest or short payload.
const MSG: &[u8] = b"lupine benchmark message -- 64-byte payload for sign/verify ops!";

// ── ML-DSA helpers ────────────────────────────────────────────────────────────

fn bench_mldsa_keygen<P: KeyGen + MlDsaParams>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen failed"));
        });
    });
}

fn bench_mldsa_sign<P: KeyGen + MlDsaParams>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    let (sk, _vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(sk.sign(black_box(MSG)).expect("sign failed"));
        });
    });
}

fn bench_mldsa_verify<P: KeyGen + MlDsaParams>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    let (sk, vk) = ml_dsa_generate_keypair::<P>(&mut rng).expect("keygen failed");
    let sig = sk.sign(MSG).expect("sign failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            black_box(
                vk.verify(black_box(MSG), black_box(&sig))
                    .expect("verify failed"),
            );
        });
    });
}

// ── Hybrid Ed25519+ML-DSA helpers ─────────────────────────────────────────────

fn bench_hybrid_keygen<P: KeyGen + MlDsaParams>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ =
                black_box(hybrid_generate_keypair::<P>(&mut rng).expect("hybrid keygen failed"));
        });
    });
}

fn bench_hybrid_sign<P: KeyGen + MlDsaParams>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    let (sk, _vk) = hybrid_generate_keypair::<P>(&mut rng).expect("hybrid keygen failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(sk.sign(black_box(MSG)).expect("hybrid sign failed"));
        });
    });
}

fn bench_hybrid_verify<P: KeyGen + MlDsaParams>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    let (sk, vk) = hybrid_generate_keypair::<P>(&mut rng).expect("hybrid keygen failed");
    let sig = sk.sign(MSG).expect("hybrid sign failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            black_box(
                vk.verify(black_box(MSG), black_box(&sig))
                    .expect("hybrid verify failed"),
            );
        });
    });
}

// ── SLH-DSA helpers ───────────────────────────────────────────────────────────

/// Criterion configuration for SLH-DSA: reduced sample count + extended
/// measurement time to accommodate the much slower signing operations.
fn slhdsa_criterion() -> Criterion {
    Criterion::default()
        .sample_size(10)
        .measurement_time(Duration::from_secs(30))
}

fn bench_slhdsa_keygen<P: ParameterSet>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ =
                black_box(slh_dsa_generate_keypair::<P>(&mut rng).expect("slh-dsa keygen failed"));
        });
    });
}

fn bench_slhdsa_sign<P: ParameterSet>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    let (sk, _vk) = slh_dsa_generate_keypair::<P>(&mut rng).expect("slh-dsa keygen failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(sk.sign(black_box(MSG)).expect("slh-dsa sign failed"));
        });
    });
}

fn bench_slhdsa_verify<P: ParameterSet>(c: &mut Criterion, name: &str) {
    let mut rng = rand::rng();
    let (sk, vk) = slh_dsa_generate_keypair::<P>(&mut rng).expect("slh-dsa keygen failed");
    let sig = sk.sign(MSG).expect("slh-dsa sign failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            black_box(
                vk.verify(black_box(MSG), black_box(&sig))
                    .expect("slh-dsa verify failed"),
            );
        });
    });
}

// ── Benchmark groups ──────────────────────────────────────────────────────────

fn mldsa_benchmarks(c: &mut Criterion) {
    bench_mldsa_keygen::<ml_dsa::MlDsa44>(c, "ML-DSA-44/keygen");
    bench_mldsa_sign::<ml_dsa::MlDsa44>(c, "ML-DSA-44/sign");
    bench_mldsa_verify::<ml_dsa::MlDsa44>(c, "ML-DSA-44/verify");

    bench_mldsa_keygen::<ml_dsa::MlDsa65>(c, "ML-DSA-65/keygen");
    bench_mldsa_sign::<ml_dsa::MlDsa65>(c, "ML-DSA-65/sign");
    bench_mldsa_verify::<ml_dsa::MlDsa65>(c, "ML-DSA-65/verify");

    bench_mldsa_keygen::<ml_dsa::MlDsa87>(c, "ML-DSA-87/keygen");
    bench_mldsa_sign::<ml_dsa::MlDsa87>(c, "ML-DSA-87/sign");
    bench_mldsa_verify::<ml_dsa::MlDsa87>(c, "ML-DSA-87/verify");
}

fn hybrid_sign_benchmarks(c: &mut Criterion) {
    bench_hybrid_keygen::<ml_dsa::MlDsa44>(c, "Hybrid-Sign-44/keygen");
    bench_hybrid_sign::<ml_dsa::MlDsa44>(c, "Hybrid-Sign-44/sign");
    bench_hybrid_verify::<ml_dsa::MlDsa44>(c, "Hybrid-Sign-44/verify");

    bench_hybrid_keygen::<ml_dsa::MlDsa65>(c, "Hybrid-Sign-65/keygen");
    bench_hybrid_sign::<ml_dsa::MlDsa65>(c, "Hybrid-Sign-65/sign");
    bench_hybrid_verify::<ml_dsa::MlDsa65>(c, "Hybrid-Sign-65/verify");

    bench_hybrid_keygen::<ml_dsa::MlDsa87>(c, "Hybrid-Sign-87/keygen");
    bench_hybrid_sign::<ml_dsa::MlDsa87>(c, "Hybrid-Sign-87/sign");
    bench_hybrid_verify::<ml_dsa::MlDsa87>(c, "Hybrid-Sign-87/verify");
}

fn slhdsa_benchmarks(c: &mut Criterion) {
    // Level 1, small (reference baseline — smallest signature, slowest signing)
    bench_slhdsa_keygen::<slh_dsa::Sha2_128s>(c, "SLH-DSA-SHA2-128s/keygen");
    bench_slhdsa_sign::<slh_dsa::Sha2_128s>(c, "SLH-DSA-SHA2-128s/sign");
    bench_slhdsa_verify::<slh_dsa::Sha2_128s>(c, "SLH-DSA-SHA2-128s/verify");

    // Level 1, fast (same level as 128s, fast-mode trade-off)
    bench_slhdsa_keygen::<slh_dsa::Sha2_128f>(c, "SLH-DSA-SHA2-128f/keygen");
    bench_slhdsa_sign::<slh_dsa::Sha2_128f>(c, "SLH-DSA-SHA2-128f/sign");
    bench_slhdsa_verify::<slh_dsa::Sha2_128f>(c, "SLH-DSA-SHA2-128f/verify");

    // Level 5, small (highest security level)
    bench_slhdsa_keygen::<slh_dsa::Sha2_256s>(c, "SLH-DSA-SHA2-256s/keygen");
    bench_slhdsa_sign::<slh_dsa::Sha2_256s>(c, "SLH-DSA-SHA2-256s/sign");
    bench_slhdsa_verify::<slh_dsa::Sha2_256s>(c, "SLH-DSA-SHA2-256s/verify");
}

criterion_group!(mldsa_benches, mldsa_benchmarks);
criterion_group!(hybrid_benches, hybrid_sign_benchmarks);
criterion_group! {
    name = slhdsa_benches;
    config = slhdsa_criterion();
    targets = slhdsa_benchmarks
}
criterion_main!(mldsa_benches, hybrid_benches, slhdsa_benches);
