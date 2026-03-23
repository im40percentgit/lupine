## Project Overview
**Type:** Rust library + CLI (post-quantum cryptography)
**Languages:** Rust (100%)
**Root:** `/home/j/projects/wolf/lupine`

### Architecture
- `crates/lupine-core/` -- Core types, traits, error handling, algorithm enums, SecurityLevel taxonomy
- `crates/lupine-kem/` -- ML-KEM (FIPS 203) wrappers + hybrid X25519+ML-KEM with KitchenSink combiner
- `crates/lupine-sign/` -- ML-DSA (FIPS 204) + SLH-DSA (FIPS 205) wrappers + hybrid Ed25519+ML-DSA
- `crates/lupine-serial/` -- DER/PEM/SPKI/composite serialization with NIST OIDs
- `crates/lupine-cli/` -- CLI interface (keygen, encapsulate, decapsulate, sign, verify) for all 24 algorithm variants
- `crates/lupine/` -- Top-level facade re-exporting all constituent crates
- `fuzz/` -- Cargo-fuzz harnesses (DER decode, PEM parse, SPKI decode)

### Active Work
- Worktree: `feature/canus-lupus-layer1` — Layer 1 high-level easy API (`lupine::easy`)
- Main branch at `6118942` (post-zeroize merge)
- All 296 tests passing, 3 fuzz targets defined
- Phase 7 (Benchmarks) completed; Phase 6b (Zeroize) completed
- Next: Layer 1 easy API (this worktree), then canus-lupus CLI (Layer 2)

---

## Original Intent

Build Lupine: a Rust post-quantum cryptographic suite implementing FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) with hybrid classical+PQC modes, DER/PEM serialization, and a CLI tool. The library wraps RustCrypto crates (`ml-kem`, `ml-dsa`, `slh-dsa`) with a consistent, ergonomic API surface.

## Problem Statement

Lupine has complete cryptographic functionality across 24 algorithm parameter sets but lacks performance data. PQC algorithms exhibit extreme variance in key sizes (32 B to 2592 B for public keys), signature sizes (64 B to 49856 B), and execution time (microseconds for ML-KEM to seconds for SLH-DSA). Without published benchmarks, API consumers cannot make informed algorithm selection decisions, and the library cannot be evaluated against competing PQC implementations (liboqs, pqcrypto, BoringSSL PQ). Every production-grade cryptography library publishes performance numbers.

## Goals & Non-Goals

### Goals
- REQ-GOAL-001: Provide criterion benchmarks for all major cryptographic operations across all algorithm families
- REQ-GOAL-002: Produce a human-readable performance comparison table in the repository (markdown)
- REQ-GOAL-003: Identify the relative cost of Lupine's wrapper overhead vs. raw RustCrypto operations
- REQ-GOAL-004: Establish a reproducible benchmark methodology that can be re-run as dependencies upgrade

### Non-Goals
- REQ-NOGO-001: Performance optimization -- benchmarks identify hotspots; optimization is Phase 7b or later
- REQ-NOGO-002: Continuous benchmark tracking (e.g., criterion.rs GitHub Action) -- that is Phase 9 (CI/CD)
- REQ-NOGO-003: Cross-platform benchmark comparison -- benchmarks run on the developer's machine; portable CI benchmarks are Phase 9
- REQ-NOGO-004: Benchmarking serialization (DER/PEM) -- serialization is not on the critical path; crypto operations dominate

## Requirements

### Must-Have (P0)
- REQ-P0-001: Criterion benchmark group for ML-KEM keygen/encapsulate/decapsulate across 512/768/1024
  Acceptance: `cargo bench --bench kem` runs without error and produces criterion output for all 3 parameter sets x 3 operations (9 benchmarks)
- REQ-P0-002: Criterion benchmark group for ML-DSA keygen/sign/verify across 44/65/87
  Acceptance: `cargo bench --bench sign` runs without error and produces criterion output for all 3 parameter sets x 3 operations (9 benchmarks)
- REQ-P0-003: Criterion benchmark group for SLH-DSA keygen/sign/verify for a representative subset (SHA2-128s, SHA2-128f, SHAKE-128s as minimum)
  Acceptance: `cargo bench --bench sign` includes SLH-DSA benchmarks for at least 3 parameter sets
- REQ-P0-004: Criterion benchmark group for hybrid KEM (X25519+ML-KEM) keygen/encapsulate/decapsulate across 512/768/1024
  Acceptance: `cargo bench --bench kem` includes hybrid KEM benchmarks for all 3 parameter sets
- REQ-P0-005: Criterion benchmark group for hybrid sign (Ed25519+ML-DSA) keygen/sign/verify across 44/65/87
  Acceptance: `cargo bench --bench sign` includes hybrid sign benchmarks for all 3 parameter sets
- REQ-P0-006: Performance summary table in repository as `BENCHMARKS.md`
  Acceptance: File exists at project root with columns: Algorithm, Operation, Time (median), Throughput (if applicable)

### Nice-to-Have (P1)
- REQ-P1-001: Benchmark all 12 SLH-DSA parameter sets (not just the representative subset)
- REQ-P1-002: Compare Lupine wrapper overhead vs. direct RustCrypto API calls for ML-KEM-768 and ML-DSA-65
- REQ-P1-003: Key/signature/ciphertext size comparison table alongside timing data

### Future Consideration (P2)
- REQ-P2-001: Memory allocation profiling (heap allocations per operation)
- REQ-P2-002: `no_std` benchmark comparison (with alloc feature vs. std)
- REQ-P2-003: Benchmark serialization layer (DER encode/decode, PEM encode/decode)

## Definition of Done

- All P0 benchmarks run successfully with `cargo bench`
- `BENCHMARKS.md` exists with populated timing data
- Benchmark code follows the established crate patterns (generic helpers, type aliases)
- No regressions in existing test suite (296 tests still pass)

## Architectural Decisions

Decisions documented here become `@decision` annotations in code during implementation.

- DEC-BENCH-001: Criterion as the benchmark framework -- it is the de facto Rust benchmark standard, produces statistical analysis (confidence intervals, regression detection), and generates HTML reports. No research needed; this is well-understood territory.
- DEC-BENCH-002: Benchmark crate location -- benchmarks live in `crates/lupine-kem/benches/` and `crates/lupine-sign/benches/` rather than a separate benchmark crate. This keeps benchmarks close to the code they measure and avoids adding a workspace member just for benchmarks.
- DEC-BENCH-003: SLH-DSA subset strategy -- SLH-DSA has 12 parameter sets. Full benchmarks for all 12 take >10 minutes. P0 benchmarks cover 3 representative sets (SHA2-128s, SHA2-128f, SHAKE-128s) spanning the s/f tradeoff and both hash families. P1 extends to all 12.
- DEC-BENCH-004: Release-mode only -- ML-DSA-87 and SLH-DSA operations overflow the default stack in debug mode. All benchmarks run in release mode (criterion's default), which also produces realistic performance numbers.

## Phase 1: Core Types & ML-KEM Wrappers
**Status:** completed
**Issues:** (predates issue tracking)

Implemented `lupine-core` (Error, SecurityLevel, KemAlgorithm, SignAlgorithm, SharedSecret) and `lupine-kem` (ML-KEM-512/768/1024 keygen, encapsulate, decapsulate with byte-oriented API).

### Decision Log
- DEC-CORE-001: Single unified Error enum (accepted)
- DEC-CORE-002: Five-level SecurityLevel enum (accepted)
- DEC-CORE-003: Separate KemAlgorithm/SignAlgorithm enums (accepted)
- DEC-CORE-004: SharedSecret as opaque newtype with zeroize-on-drop (accepted)
- DEC-KEM-001: Generic wrapper over KemCore (accepted)
- DEC-KEM-002: Byte-vec serialization at API boundary (accepted)
- DEC-KEM-003: Manual Drop for MlKemSecretKey instead of ZeroizeOnDrop derive (accepted)

## Phase 2: ML-DSA & SLH-DSA Signatures
**Status:** completed
**Issues:** (predates issue tracking)

Implemented `lupine-sign` with ML-DSA (FIPS 204) for parameter sets 44/65/87 and SLH-DSA (FIPS 205) for all 12 parameter sets. Seed-based signing key serialization for ML-DSA. Both deterministic and randomized signing for SLH-DSA.

### Decision Log
- DEC-SIGN-001: Seed-based signing key serialization for ML-DSA (accepted)
- DEC-SIGN-002: Native API approach to avoid signature 2.x/3.x conflict (accepted)
- DEC-SIGN-003: Vec<u8> for SLH-DSA signature bytes at wrapper boundary (accepted)
- DEC-SIGN-004: Deterministic signing as default for SLH-DSA (accepted)
- DEC-SIGN-005: Manual Drop for MlDsaSigningKey instead of ZeroizeOnDrop derive (accepted)
- DEC-SIGN-006: Manual Drop for SlhDsaSigningKey instead of ZeroizeOnDrop derive (accepted)

## Phase 3: Hybrid Cryptographic Modes
**Status:** completed
**Issues:** (predates issue tracking)

Implemented hybrid X25519+ML-KEM KEM with KitchenSink HKDF-SHA-256 combiner. Implemented hybrid Ed25519+ML-DSA signatures with AND-verify semantics. Both generic over ML-KEM/ML-DSA parameter sets.

### Decision Log
- DEC-HYBRID-KEM-001: KitchenSink combiner vs XOR/concatenation (accepted)
- DEC-HYBRID-KEM-002: X25519 ephemeral public as ciphertext component (accepted)
- DEC-HYBRID-KEM-003: Generic over ML-KEM parameter set (accepted)
- DEC-HYBRID-SIGN-001: AND-verify over threshold/OR semantics (accepted)
- DEC-HYBRID-SIGN-002: Native API to avoid signature version conflict (accepted)

## Phase 4: DER/PEM/SPKI Serialization
**Status:** completed
**Issues:** (predates issue tracking)

Implemented `lupine-serial` with DER encoding (SEQUENCE { AlgorithmIdentifier, OCTET STRING }), PEM wrapping (RFC 7468), SPKI encoding (SubjectPublicKeyInfo with BIT STRING), composite encoding for hybrid types, and NIST OID constants for all algorithms plus Lupine private-arc OIDs for hybrid types.

### Decision Log
- DEC-SERIAL-001: NIST CSOR OIDs (final, not draft) (accepted)
- DEC-SERIAL-002: Minimal KeyInfo vs full PKCS8 (accepted)
- DEC-SERIAL-003: Standard PEM labels for PQC keys (accepted)
- DEC-SERIAL-004: Manual SPKI encoder vs spki RC crate (accepted)
- DEC-SERIAL-005: DER SEQUENCE for composite format (accepted)
- DEC-SERIAL-006: Integration test scope: synthetic bytes + real ML-KEM keys (accepted)

## Phase 5: CLI Interface
**Status:** completed
**Issues:** (predates issue tracking)

Implemented `lupine-cli` with subcommands: keygen, encapsulate, decapsulate, sign, verify. Supports all 24 algorithm variants via CliAlgorithm enum and callback-macro dispatch. Raw/DER/PEM format support. Large-stack thread wrapper for SLH-DSA compatibility.

### Decision Log
- DEC-CLI-001: Single flat CliAlgorithm enum for all 24 parameter sets (accepted)
- DEC-CLI-002: Unified --format flag with PEM default (accepted)
- DEC-CLI-003: Composite encoder for hybrid keys (accepted)
- DEC-CLI-004: Callback-macro dispatch pattern (accepted)
- DEC-CLI-005: Inline callback macros per command rather than shared generic functions (accepted)
- DEC-CLI-006: Ciphertext always written as raw bytes regardless of --format (accepted)
- DEC-CLI-007: --pub-key required for hybrid KEM raw-format decapsulation (accepted)
- DEC-CLI-008: Stdin as default message source for sign and verify (accepted)
- DEC-CLI-009: Exit code 1 (not panic) on verification failure (accepted)
- DEC-CLI-010: Large-stack thread wrapper for SLH-DSA (accepted)

## Phase 6a: Correctness & Validation Test Suite
**Status:** completed
**Issues:** (predates issue tracking)

Added KAT (Known Answer Test) vectors for ML-KEM and ML-DSA. Property-based tests with proptest for KEM and signature operations. Integration tests for the serialization layer. 296 total tests passing.

### Decision Log
- DEC-TEST-KEM-001: Deterministic RNG via StdRng::from_seed for KAT tests (accepted)
- DEC-TEST-KEM-002: Integration roundtrip tests separate from inline unit tests (accepted)
- DEC-TEST-KEM-003: Proptest case counts: 20 for ML-KEM, 10 for hybrid (accepted)
- DEC-TEST-SIGN-001: StdRng::from_seed for deterministic KAT vectors in lupine-sign (accepted)
- DEC-TEST-SIGN-002: SLH-DSA roundtrip tests limited to 3 representative variants (accepted)
- DEC-TEST-SIGN-003: Proptest case counts: 20 for ML-DSA, 10 for hybrid, 3 for SLH-DSA (accepted)

## Phase 6b: Zeroize / Memory Safety
**Status:** completed
**Issues:** (predates issue tracking — merged as feature/zeroize)

Added `Zeroize` and `ZeroizeOnDrop` to all secret key types: `MlKemSecretKey`, `MlDsaSigningKey`, `SlhDsaSigningKey`, `HybridKemSecretKey`, `HybridSigningKey`. Used manual `Drop` impls where `derive` cannot be used due to non-Zeroize fields. Defense-in-depth applied to non-secret but key-adjacent bytes (e.g., cached public key bytes in `HybridKemSecretKey`).

### Decision Log
- DEC-KEM-003: Manual Drop for MlKemSecretKey instead of ZeroizeOnDrop derive (accepted) — in Phase 1 log
- DEC-SIGN-005: Manual Drop for MlDsaSigningKey instead of ZeroizeOnDrop derive (accepted) — in Phase 2 log
- DEC-SIGN-006: Manual Drop for SlhDsaSigningKey instead of ZeroizeOnDrop derive (accepted) — in Phase 2 log

## Phase 7: Benchmarks + Performance
**Status:** completed
**Decision IDs:** DEC-BENCH-001, DEC-BENCH-002, DEC-BENCH-003, DEC-BENCH-004
**Requirements:** REQ-P0-001, REQ-P0-002, REQ-P0-003, REQ-P0-004, REQ-P0-005, REQ-P0-006
**Issues:** #1, #2, #3, #4
**Definition of Done:**
- REQ-P0-001 satisfied: `cargo bench --bench kem` produces criterion output for ML-KEM 512/768/1024 x keygen/encapsulate/decapsulate
- REQ-P0-002 satisfied: `cargo bench --bench sign` produces criterion output for ML-DSA 44/65/87 x keygen/sign/verify
- REQ-P0-003 satisfied: `cargo bench --bench sign` includes SLH-DSA benchmarks for SHA2-128s, SHA2-128f, SHAKE-128s
- REQ-P0-004 satisfied: `cargo bench --bench kem` includes hybrid KEM benchmarks for 512/768/1024
- REQ-P0-005 satisfied: `cargo bench --bench sign` includes hybrid sign benchmarks for 44/65/87
- REQ-P0-006 satisfied: `BENCHMARKS.md` exists at project root with Algorithm, Operation, Time columns

### Planned Decisions
- DEC-BENCH-001: Criterion as benchmark framework -- de facto Rust standard, statistical analysis, HTML reports -- Addresses: REQ-GOAL-001, REQ-GOAL-004
- DEC-BENCH-002: Benchmarks in per-crate benches/ dirs -- keeps benchmarks close to measured code, no extra workspace member -- Addresses: REQ-GOAL-001
- DEC-BENCH-003: SLH-DSA representative subset (3 of 12) for P0 -- full 12 takes >10 min, subset covers s/f tradeoff and both hash families -- Addresses: REQ-P0-003
- DEC-BENCH-004: Release-mode only -- avoids stack overflow in debug, produces realistic perf numbers -- Addresses: REQ-GOAL-001

### Implementation Plan

**Task 1: KEM benchmarks** (Issue #1)
- Add `criterion` dev-dependency to `lupine-kem/Cargo.toml`
- Create `crates/lupine-kem/benches/kem.rs` with benchmark groups:
  - `mlkem_keygen` -- ML-KEM keygen for 512/768/1024
  - `mlkem_encapsulate` -- ML-KEM encapsulate for 512/768/1024
  - `mlkem_decapsulate` -- ML-KEM decapsulate for 512/768/1024
  - `hybrid_kem_keygen` -- X25519+ML-KEM keygen for 512/768/1024
  - `hybrid_kem_encapsulate` -- X25519+ML-KEM encapsulate for 512/768/1024
  - `hybrid_kem_decapsulate` -- X25519+ML-KEM decapsulate for 512/768/1024
- Use a generic helper function parameterized on `P: KemCore` (same pattern as tests)
- Pre-generate keys in benchmark setup; measure only the operation under test

**Task 2: ML-DSA benchmarks** (Issue #2)
- Add `criterion` dev-dependency to `lupine-sign/Cargo.toml`
- Create `crates/lupine-sign/benches/sign.rs` with benchmark groups:
  - `mldsa_keygen` -- ML-DSA keygen for 44/65/87
  - `mldsa_sign` -- ML-DSA sign for 44/65/87
  - `mldsa_verify` -- ML-DSA verify for 44/65/87
  - `hybrid_sign_keygen` -- Ed25519+ML-DSA keygen for 44/65/87
  - `hybrid_sign_sign` -- Ed25519+ML-DSA sign for 44/65/87
  - `hybrid_sign_verify` -- Ed25519+ML-DSA verify for 44/65/87
- Pre-generate keys and message in setup; use deterministic signing
- ML-DSA-87 benchmarks need release mode (criterion default); no stack concern

**Task 3: SLH-DSA benchmarks** (Issue #3)
- Add SLH-DSA benchmark groups to the same `sign.rs` bench file:
  - `slhdsa_keygen` -- SLH-DSA keygen for SHA2-128s, SHA2-128f, SHAKE-128s (P0)
  - `slhdsa_sign` -- SLH-DSA sign for the same 3 sets
  - `slhdsa_verify` -- SLH-DSA verify for the same 3 sets
- P1: extend to all 12 parameter sets (gated behind a `full-bench` feature or just included)
- Use `criterion::measurement::WallTime` with appropriate sample sizes (SLH-DSA signing is slow; reduce sample count for large parameter sets)

**Task 4: BENCHMARKS.md + performance summary** (Issue #4)
- Run all benchmarks on the development machine
- Collect median times from criterion output
- Write `BENCHMARKS.md` at project root with:
  - Hardware description (CPU, RAM, OS, rustc version)
  - Table columns: Algorithm, Operation, Median Time, Key/Sig/CT Size
  - Sections: KEM (pure + hybrid), Signatures (ML-DSA + SLH-DSA + hybrid)
  - Notes on methodology (release mode, criterion defaults, warm-up)
- Depends on Tasks 1-3 completing first

### Decision Log
- DEC-BENCH-001: Criterion as benchmark framework (accepted)
- DEC-BENCH-002: Benchmarks in per-crate benches/ dirs (accepted)
- DEC-BENCH-003: SLH-DSA representative subset (3 of 12) for P0 (accepted)
- DEC-BENCH-004: Release-mode only benchmarks (accepted)
- DEC-BENCH-KEM-001: One Criterion group per operation family for KEM benchmarks (accepted)
- DEC-BENCH-SIGN-001: Separate Criterion groups per algorithm family for sign benchmarks (accepted)
- DEC-BENCH-SIGN-002: SLH-DSA benchmarks scoped to 3 of 12 parameter sets (accepted)

## Phase 12: Layer 1 — High-Level Easy API
**Status:** in-progress
**Branch:** `feature/canus-lupus-layer1`
**Issues:** (canus-lupus design doc: `~/.gstack/projects/im40percentgit-lupine/j-main-design-20260322-192206.md`)
**Definition of Done:**
- `lupine::easy::generate_keys()`, `encrypt()`, `decrypt()`, `sign()`, `verify()` work end-to-end
- KEM-DEM construction: HKDF-SHA-256 + ChaCha20-Poly1305 with v1 wire format
- All new tests pass; existing 296 tests have zero regressions
- `cargo clippy --workspace -- -D warnings` clean

### Planned Decisions
- DEC-EASY-001: KEM-DEM construction with HKDF-SHA-256 + ChaCha20-Poly1305 (accepted)
- DEC-EASY-002: Version-byte wire format for algorithm agility (accepted)
- DEC-EASY-003: AAD = version_byte || KEM_ciphertext for binding (accepted)

### Implementation Plan
- `crates/lupine/src/easy.rs` — new module with Error, Keypair, generate_keys, encrypt, decrypt, sign, verify
- `crates/lupine/src/lib.rs` — conditional `pub mod easy` behind `easy` feature
- `crates/lupine/Cargo.toml` — `easy` feature (default-on) gating chacha20poly1305, hkdf, sha2, rand
- Workspace `Cargo.toml` — add chacha20poly1305 = "0.10"

## Phase 8: Documentation & Examples (planned)
**Status:** planned
**Requirements:** Rustdoc for all public API items, example programs, crate-level documentation
**Definition of Done:** `cargo doc --no-deps --workspace` produces clean output; at least 3 example programs in `examples/`

## Phase 9: CI/CD (planned)
**Status:** planned
**Requirements:** GitHub Actions for test, clippy, fmt, MSRV check; optional benchmark regression tracking
**Definition of Done:** PRs are gated on CI passing; benchmark results archived per commit

## Phase 10: Security Hardening (planned)
**Status:** planned
**Requirements:** Zeroize audit (all secret key paths), constant-time comparison where needed, unsafe review
**Definition of Done:** Audit checklist completed; no secret material left unzeroized on any code path

## Phase 11: crates.io Readiness (planned)
**Status:** planned
**Requirements:** LICENSE files, Cargo.toml metadata, README per crate, publish dry-run
**Definition of Done:** `cargo publish --dry-run` succeeds for all 6 crates in dependency order

## References

- FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final
- FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final
- FIPS 205 (SLH-DSA): https://csrc.nist.gov/pubs/fips/205/final
- RustCrypto ml-kem: https://docs.rs/ml-kem/0.2
- RustCrypto ml-dsa: https://github.com/RustCrypto/signatures/tree/master/ml-dsa
- RustCrypto slh-dsa: https://github.com/RustCrypto/signatures/tree/master/slh-dsa
- Criterion.rs: https://bheisler.github.io/criterion.rs/book/
- NIST CSOR OID assignments: https://csrc.nist.gov/projects/computer-security-objects-register

## Worktree Strategy

Main is sacred. Phase 7 work happens in a feature worktree:
- Branch: `feature/phase7-benchmarks`
- Worktree: `.worktrees/phase7-benchmarks`
- Merge to main only after all P0 requirements satisfied and benchmarks run clean
