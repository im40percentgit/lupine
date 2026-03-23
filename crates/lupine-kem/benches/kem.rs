//! Criterion benchmarks for lupine-kem.
//!
//! Measures keygen, encapsulate, and decapsulate for all three ML-KEM
//! parameter sets (512, 768, 1024) and the three hybrid X25519+ML-KEM
//! parameter sets.
//!
//! # Running
//!
//! ```
//! cargo bench -p lupine-kem
//! ```
//!
//! @decision DEC-BENCH-KEM-001
//! @title Bench structure: one group per operation family
//! @status accepted
//! @rationale Criterion groups by operation (keygen, encapsulate, decapsulate)
//!   make it easy to compare parameter sets within a single plot. Grouping by
//!   algorithm family instead would obscure the relative cost of each operation.
//!   ML-KEM and Hybrid KEM are in separate groups because they have different
//!   key structures and cost profiles: the hybrid adds an X25519 DH on top of
//!   ML-KEM, so separating the groups highlights that overhead clearly.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ml_kem::{
    kem::{Decapsulate, Encapsulate},
    EncodedSizeUser, KemCore,
};
use rand::rngs::OsRng;

use lupine_kem::{generate_keypair as mlkem_keygen, hybrid::generate_keypair as hybrid_keygen};

// ── ML-KEM helpers ────────────────────────────────────────────────────────────

fn bench_mlkem_keygen<P>(c: &mut Criterion, name: &str)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser,
{
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(mlkem_keygen::<P>(&mut OsRng).expect("keygen failed"));
        });
    });
}

fn bench_mlkem_encapsulate<P>(c: &mut Criterion, name: &str)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (_sk, pk) = mlkem_keygen::<P>(&mut OsRng).expect("keygen failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(pk.encapsulate(&mut OsRng).expect("encapsulate failed"));
        });
    });
}

fn bench_mlkem_decapsulate<P>(c: &mut Criterion, name: &str)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = mlkem_keygen::<P>(&mut OsRng).expect("keygen failed");
    let (ct, _ss) = pk.encapsulate(&mut OsRng).expect("encapsulate failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(sk.decapsulate(black_box(&ct)).expect("decapsulate failed"));
        });
    });
}

// ── Hybrid KEM helpers ────────────────────────────────────────────────────────

fn bench_hybrid_keygen<P>(c: &mut Criterion, name: &str)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser,
{
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(hybrid_keygen::<P>(&mut OsRng).expect("hybrid keygen failed"));
        });
    });
}

fn bench_hybrid_encapsulate<P>(c: &mut Criterion, name: &str)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (_sk, pk) = hybrid_keygen::<P>(&mut OsRng).expect("hybrid keygen failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(pk.encapsulate(&mut OsRng).expect("encapsulate failed"));
        });
    });
}

fn bench_hybrid_decapsulate<P>(c: &mut Criterion, name: &str)
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    P::EncapsulationKey: EncodedSizeUser + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
{
    let (sk, pk) = hybrid_keygen::<P>(&mut OsRng).expect("hybrid keygen failed");
    let (ct, _ss) = pk.encapsulate(&mut OsRng).expect("encapsulate failed");
    c.bench_function(name, |b| {
        b.iter(|| {
            let _ = black_box(sk.decapsulate(black_box(&ct)).expect("decapsulate failed"));
        });
    });
}

// ── Benchmark groups ──────────────────────────────────────────────────────────

fn mlkem_benchmarks(c: &mut Criterion) {
    // ML-KEM-512
    bench_mlkem_keygen::<ml_kem::MlKem512>(c, "ML-KEM-512/keygen");
    bench_mlkem_encapsulate::<ml_kem::MlKem512>(c, "ML-KEM-512/encapsulate");
    bench_mlkem_decapsulate::<ml_kem::MlKem512>(c, "ML-KEM-512/decapsulate");

    // ML-KEM-768
    bench_mlkem_keygen::<ml_kem::MlKem768>(c, "ML-KEM-768/keygen");
    bench_mlkem_encapsulate::<ml_kem::MlKem768>(c, "ML-KEM-768/encapsulate");
    bench_mlkem_decapsulate::<ml_kem::MlKem768>(c, "ML-KEM-768/decapsulate");

    // ML-KEM-1024
    bench_mlkem_keygen::<ml_kem::MlKem1024>(c, "ML-KEM-1024/keygen");
    bench_mlkem_encapsulate::<ml_kem::MlKem1024>(c, "ML-KEM-1024/encapsulate");
    bench_mlkem_decapsulate::<ml_kem::MlKem1024>(c, "ML-KEM-1024/decapsulate");
}

fn hybrid_kem_benchmarks(c: &mut Criterion) {
    // Hybrid X25519+ML-KEM-512
    bench_hybrid_keygen::<ml_kem::MlKem512>(c, "Hybrid-KEM-512/keygen");
    bench_hybrid_encapsulate::<ml_kem::MlKem512>(c, "Hybrid-KEM-512/encapsulate");
    bench_hybrid_decapsulate::<ml_kem::MlKem512>(c, "Hybrid-KEM-512/decapsulate");

    // Hybrid X25519+ML-KEM-768
    bench_hybrid_keygen::<ml_kem::MlKem768>(c, "Hybrid-KEM-768/keygen");
    bench_hybrid_encapsulate::<ml_kem::MlKem768>(c, "Hybrid-KEM-768/encapsulate");
    bench_hybrid_decapsulate::<ml_kem::MlKem768>(c, "Hybrid-KEM-768/decapsulate");

    // Hybrid X25519+ML-KEM-1024
    bench_hybrid_keygen::<ml_kem::MlKem1024>(c, "Hybrid-KEM-1024/keygen");
    bench_hybrid_encapsulate::<ml_kem::MlKem1024>(c, "Hybrid-KEM-1024/encapsulate");
    bench_hybrid_decapsulate::<ml_kem::MlKem1024>(c, "Hybrid-KEM-1024/decapsulate");
}

criterion_group!(kem_benches, mlkem_benchmarks, hybrid_kem_benchmarks);
criterion_main!(kem_benches);
