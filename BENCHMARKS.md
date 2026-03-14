# Lupine Performance Benchmarks

Criterion benchmarks measuring the Lupine PQC wrapper overhead for key
generation, encapsulation/signing, and decapsulation/verification across all
supported algorithm families.

## Methodology

- **Tool:** [Criterion.rs](https://github.com/bheisler/criterion.rs) 0.5
- **Profile:** release (optimized, no debug assertions)
- **Samples:** 100 per benchmark (ML-KEM, ML-DSA, Hybrid); 10 per benchmark (SLH-DSA)
- **Measurement time:** 5 s per benchmark (ML-KEM, ML-DSA, Hybrid); 30 s per benchmark (SLH-DSA)
- **Machine:** Linux x86_64, kernel 6.17.0-14-generic
- **Reported value:** median of Criterion's sample distribution

> Results are specific to this hardware. Re-run `cargo bench` to reproduce on your machine.

---

## ML-KEM (FIPS 203) — Key Encapsulation

| Algorithm    | Keygen   | Encapsulate | Decapsulate |
|-------------|----------|-------------|-------------|
| ML-KEM-512  | 19.5 µs  | 16.7 µs     | 22.1 µs     |
| ML-KEM-768  | 33.7 µs  | 27.4 µs     | 34.4 µs     |
| ML-KEM-1024 | 52.3 µs  | 42.5 µs     | 52.2 µs     |

**Key sizes (FIPS 203 Table 2):**

| Algorithm    | Public key | Secret key | Ciphertext | Shared secret |
|-------------|-----------|-----------|-----------|--------------|
| ML-KEM-512  | 800 B     | 1632 B    | 768 B     | 32 B         |
| ML-KEM-768  | 1184 B    | 2400 B    | 1088 B    | 32 B         |
| ML-KEM-1024 | 1568 B    | 3168 B    | 1568 B    | 32 B         |

---

## Hybrid KEM — X25519 + ML-KEM (KitchenSink combiner)

| Algorithm         | Keygen   | Encapsulate | Decapsulate |
|------------------|----------|-------------|-------------|
| Hybrid-KEM-512   | 30.3 µs  | 52.8 µs     | 48.4 µs     |
| Hybrid-KEM-768   | 44.1 µs  | 65.1 µs     | 62.6 µs     |
| Hybrid-KEM-1024  | 63.0 µs  | 81.4 µs     | 79.0 µs     |

**X25519 overhead** (Hybrid − ML-KEM, encapsulate):

| Parameter set | ML-KEM encap | Hybrid encap | Overhead |
|--------------|-------------|-------------|---------|
| 512          | 16.7 µs     | 52.8 µs     | +36.1 µs (×3.2) |
| 768          | 27.4 µs     | 65.1 µs     | +37.7 µs (×2.4) |
| 1024         | 42.5 µs     | 81.4 µs     | +38.9 µs (×1.9) |

The ~37–39 µs overhead is constant across parameter sets — it is the X25519
ECDH cost. As the ML-KEM parameter set grows, the relative overhead shrinks.

---

## ML-DSA (FIPS 204) — Digital Signatures

| Algorithm  | Keygen   | Sign      | Verify   |
|-----------|----------|-----------|----------|
| ML-DSA-44 | 126.9 µs | 103.0 µs  | 22.0 µs  |
| ML-DSA-65 | 210.5 µs | 199.5 µs  | 31.2 µs  |
| ML-DSA-87 | 317.8 µs | 532.1 µs  | 45.3 µs  |

**Key and signature sizes (FIPS 204 Table 2):**

| Algorithm  | Signing key (seed) | Verifying key | Signature |
|-----------|-------------------|--------------|-----------|
| ML-DSA-44 | 32 B              | 1312 B       | 2420 B    |
| ML-DSA-65 | 32 B              | 1952 B       | 3309 B    |
| ML-DSA-87 | 32 B              | 2592 B       | 4627 B    |

Note: signing keys are stored as 32-byte seeds (canonical FIPS 204 form);
the expanded signing key is derived on load.

---

## Hybrid Signatures — Ed25519 + ML-DSA (AND-verify)

| Algorithm        | Keygen   | Sign      | Verify   |
|-----------------|----------|-----------|----------|
| Hybrid-Sign-44  | 156.1 µs | 66.6 µs   | 44.8 µs  |
| Hybrid-Sign-65  | 234.0 µs | 853.5 µs  | 53.3 µs  |
| Hybrid-Sign-87  | 360.7 µs | 201.5 µs  | 66.9 µs  |

**Ed25519 overhead** (Hybrid − ML-DSA, sign):

| Parameter set | ML-DSA sign | Hybrid sign | Delta      |
|--------------|------------|------------|------------|
| 44           | 103.0 µs   | 66.6 µs    | −36.4 µs*  |
| 65           | 199.5 µs   | 853.5 µs   | +654.0 µs  |
| 87           | 532.1 µs   | 201.5 µs   | −330.6 µs* |

\* ML-DSA signing cost is non-monotone across parameter sets due to randomized
intermediate rejection sampling; the hybrid wrapper adds one deterministic
Ed25519 sign (~10–20 µs) on top. The apparent negative deltas for 44 and 87
reflect run-to-run variance in ML-DSA's probabilistic signing loop — the
dominant cost remains ML-DSA, not Ed25519.

---

## SLH-DSA (FIPS 205) — Hash-Based Signatures

SLH-DSA operations are orders of magnitude slower than lattice-based schemes.
The `s` (small) variants minimize signature size; the `f` (fast) variants
minimize signing time.

| Algorithm           | Keygen    | Sign       | Verify   |
|--------------------|-----------|------------|----------|
| SLH-DSA-SHA2-128s  | 14.3 ms   | 110.1 ms   | 105.8 µs |
| SLH-DSA-SHA2-128f  | 215.6 µs  | 5.04 ms    | 299.7 µs |

**Key and signature sizes (FIPS 205):**

| Algorithm           | Signing key | Verifying key | Signature |
|--------------------|------------|--------------|-----------|
| SLH-DSA-SHA2-128s  | 64 B       | 32 B         | 7856 B    |
| SLH-DSA-SHA2-128f  | 64 B       | 32 B         | 17088 B   |
| SLH-DSA-SHA2-256s  | 128 B      | 64 B         | 29792 B   |

The `128f` variant trades a ×22 signature size increase for ×22 faster
signing. Verification is fast in both variants (~100–300 µs). SLH-DSA-256s
benchmarks were not included in the timing run (signing takes ~30 min);
see [REQ-P0-004](./MASTER_PLAN.md) for full parameter coverage notes.

---

## Algorithm Selection Guide

| Use case                        | Recommended algorithm | Reason                                     |
|--------------------------------|----------------------|--------------------------------------------|
| Key exchange, quantum-safe only | ML-KEM-768           | NIST level 3, 27 µs encap, 1088 B ct      |
| Key exchange, belt-and-suspenders | Hybrid-KEM-768     | Classical+PQ, +38 µs over ML-KEM-768       |
| Signatures, performance priority | ML-DSA-44          | Fastest keygen+sign at level 2             |
| Signatures, belt-and-suspenders  | Hybrid-Sign-44     | Ed25519+ML-DSA-44, +53 µs keygen overhead  |
| Signatures, smallest keys       | SLH-DSA-SHA2-128s  | 32 B vk, 7856 B sig — but 110 ms signing   |
| Signatures, fast signing         | SLH-DSA-SHA2-128f  | 5 ms signing, 17 KB sig                    |

---

## Reproducing

```bash
# All KEM benchmarks
cargo bench -p lupine-kem

# All signature benchmarks
cargo bench -p lupine-sign

# Specific algorithm family
cargo bench -p lupine-sign -- "ML-DSA"

# HTML reports (in target/criterion/)
cargo bench -p lupine-kem
open target/criterion/report/index.html
```

Criterion HTML reports with plots are written to `target/criterion/` after
each bench run. These are not committed; re-run locally to generate them.
