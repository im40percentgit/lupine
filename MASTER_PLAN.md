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
- No active worktrees — all phases complete
- All 18 phases completed (1-7, 6b, 8-17)
- 367+ tests passing (29 new SSH tests), 3 fuzz targets defined
- canus-lupus CLI: keygen, encrypt, decrypt, sign, verify, keys (with --ssh export), vault
- Published to crates.io as v0.1.0 (7 crates)

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

## Phase 8: Documentation & Examples
**Status:** completed
**Commit:** `ccf348d`

Added crate-level rustdoc to `lupine/src/lib.rs` with compile-tested quick-start example, crate map, and feature-flags table. Created 3 example programs: `encrypt_file.rs`, `sign_verify.rs`, `kem_raw.rs`. Fixed 8 rustdoc warnings across the workspace. `cargo doc --no-deps --workspace` produces clean output.

### Decision Log
(No new architectural decisions — documentation only)

## Phase 9: CI/CD
**Status:** completed
**Commit:** `fe9660a`

Added `.github/workflows/ci.yml` with 5 jobs: test (ubuntu+macos matrix), clippy (-D warnings), fmt, msrv (Rust 1.75), doc. Added `.github/workflows/security.yml` for weekly `cargo audit`. Fixed 31 pre-existing rustfmt violations to pass the fmt gate. `Swatinem/rust-cache@v2` for CI caching.

### Decision Log
- DEC-CI-001: Five-job CI matrix with hard gates on all jobs (accepted)
- DEC-CI-002: Swatinem/rust-cache@v2 for CI caching (accepted)
- DEC-CI-003: Weekly cargo audit on separate workflow (accepted)

## Phase 10: Security Hardening
**Status:** completed
**Commit:** `8a95bac`

Zeroize audit found and fixed 3 gaps: AEAD key in `easy.rs` not zeroized after encrypt/decrypt, seed bytes in `mldsa.rs` not zeroized after keypair construction, PEM-decoded key bytes in `keystore.rs` not zeroized before drop. Zero `unsafe` blocks confirmed. Created `SECURITY.md` with full audit: zeroize coverage, constant-time guarantees, and responsible disclosure.

### Decision Log
- DEC-SEC-001: Unconditional zeroize on both success and error paths for AEAD keys (accepted)
- DEC-SEC-002: Defense-in-depth zeroize of intermediate seed bytes even when moved (accepted)
- DEC-SEC-003: SECURITY.md as the canonical audit document (accepted)

## Phase 11: crates.io Readiness
**Status:** completed
**Commit:** `24031cc`

Added `LICENSE-MIT` and `LICENSE-APACHE` at workspace root. Created `README.md` for all 7 crates and workspace root. Added crates.io metadata (keywords, categories, repository, homepage) to all Cargo.toml files. Added version specs to all workspace path dependencies. `cargo publish -p lupine-core --dry-run` passes.

### Decision Log
- DEC-PUB-001: Dual MIT/Apache-2.0 license with separate LICENSE files (accepted)
- DEC-PUB-002: Per-crate README.md for crates.io listing (accepted)
- DEC-PUB-003: Version-aligned path deps at 0.1.0 for initial publish (accepted)

## Phase 12: canus-lupus — Unified PQC CLI
**Status:** completed
**Design doc:** `~/.gstack/projects/im40percentgit-lupine/j-main-design-20260322-192206.md`

Three layers shipped:

### Layer 1: High-Level Easy API (`5e17e5a`)
Added `lupine::easy` module with `generate_keys()`, `encrypt()`, `decrypt()`, `sign()`, `verify()`. KEM-DEM construction: HKDF-SHA-256 + ChaCha20-Poly1305. Feature-gated behind default-on `easy` flag. 12 unit tests + 2 doctests.

### Decision Log
- DEC-EASY-001: KEM-DEM construction with HKDF-SHA-256 + ChaCha20-Poly1305 (accepted)
- DEC-EASY-002: Version-byte wire format for algorithm agility (accepted)
- DEC-EASY-003: AAD = version_byte || KEM_ciphertext for binding (accepted)

### Layer 2: CLI Binary (`48df7f9`)
Added `crates/canus-lupus/` with 7 subcommands: keygen, encrypt, decrypt, sign, verify, keys (list/import/export). Key storage at `~/.canus-lupus/keys/` with PEM files. `CANUS_LUPUS_HOME` env override. 15 integration tests.

### Decision Log
- DEC-CLI-020: Large-stack thread for ML-DSA compatibility in canus-lupus main (accepted)
- DEC-CLI-021: Encrypt-for-self as default behavior (accepted)
- DEC-CLI-022: Decrypt requires full keypair load (SK + PK together) (accepted)
- DEC-CLI-023: Raw signature bytes stored directly — no PEM wrapper on .sig files (accepted)
- DEC-CLI-024: verify exits non-zero on invalid signature (accepted)
- DEC-CLI-025: Public key bundle format: two PEM blocks concatenated (accepted)
- DEC-KEYSTORE-001: PEM storage with raw key bytes (no DER wrapper) (accepted)
- DEC-KEYSTORE-002: Always load KEM SK and KEM PK together (accepted)

### Layer 3: Vault (`1169608`)
Added vault subcommands: init, set, get, list, rm. Encrypted secret storage using `lupine::easy::encrypt()`. Hierarchical filesystem layout, path traversal protection, stdin piping, empty dir pruning. 8 unit tests + 9 integration tests.

### Decision Log
- DEC-VAULT-001: Encrypt vault entries to the default KEM public key (accepted)
- DEC-VAULT-002: Hierarchical paths stored as directory trees (accepted)
- DEC-VAULT-003: vault get writes plaintext without trailing newline (accepted)
- DEC-VAULT-004: vault set reads value from stdin when no argument is given (accepted)
- DEC-TEST-001: Use CANUS_LUPUS_HOME env var for test isolation (accepted)

### Example Programs
Added 3 example programs in `crates/lupine/examples/`: `encrypt_file.rs`, `sign_verify.rs`, `kem_raw.rs`.

### Decision Log
- DEC-EXAMPLE-001: Example programs use `lupine::easy`, not raw primitives (accepted)
- DEC-EXAMPLE-002: Hybrid Ed25519+ML-DSA-65 as the default signing algorithm in examples (accepted)
- DEC-EXAMPLE-003: kem_raw uses ML-KEM-768 (not 512 or 1024) as the illustrative set (accepted)

## Phase 13: no_std CI Validation
**Status:** completed
**Commit:** `5ee2b13`

Added CI job (`no_std (thumbv7em)`) that checks `lupine-core`, `lupine-kem`, and `lupine-serial` compile on `thumbv7em-none-eabi` with `--no-default-features --features alloc`. Fixed real no_std bugs: removed phantom deps on `lupine-sign` from `lupine-serial`, disabled default features on `rand`/`ml-kem` at workspace level, fixed `alloc::vec!` and `ToOwned` imports.

### Decision Log
- DEC-NOSTD-001: Use cargo check not cargo test — no test harness on bare-metal targets (accepted)
- DEC-NOSTD-002: Exclude lupine-sign — ml-dsa/slh-dsa RC crates require std (accepted)
- DEC-CI-004: Check all three no_std-capable crates, not just lupine-serial (accepted)

## Phase 14: SSH Key Serialization
**Status:** completed
**Commits:** `fef285d`, `d033f37`

New `ssh` module in `lupine-serial` implementing the `openssh-key-v1` binary format for all KEM and signature key types. Algorithm names use `@lupine.dev` domain. 29 tests covering round-trips, edge cases, and error paths. Added `base64ct` dependency (constant-time, no_std compatible). CLI integration: `canus-lupus keys export --ssh <name>`.

### Decision Log
- DEC-SERIAL-006: SSH algorithm names use `@lupine.dev` namespace (accepted)
- DEC-SERIAL-007: SLH-DSA not supported in SSH format — signature sizes incompatible with SSH transport (accepted)
- DEC-SERIAL-008: Check value 0x12345678 for deterministic unencrypted openssh-key-v1 output (accepted)

## Phase 15: X.509 Certificates (lupine-cert)
**Status:** completed
**Commits:** `4b33ef3`..`f5039a8`

New `lupine-cert` crate with X.509v3 certificate support:
- **ASN.1 structures:** AlgorithmIdentifier, TbsCertificate, X509Certificate with manual DER encoding for version tag and RDN sequences
- **Generation:** Self-signed and CA-signed certificates for ML-DSA-44/65/87 and hybrid Ed25519+ML-DSA-44/65/87 via `CertBuilder`
- **Parsing:** DER and PEM certificate parsing with `Certificate` type (subject/issuer CN, keys, signature extraction)
- **Validation:** `verify_self_signed()` and `verify_chain()` with OID-based algorithm dispatch
- **CLI:** `canus-lupus cert generate`, `cert inspect`, `cert verify-chain` subcommands
- 42 tests in lupine-cert + 6 CLI tests

### Decision Log
- DEC-CERT-001: Manual ASN.1 encoding with der 0.8 — avoids x509-cert RC crate (accepted)
- DEC-CERT-002: CertAlgorithm enum separate from SignAlgorithm — covers both pure and hybrid without modifying lupine-core (accepted)
- DEC-CERT-003: No CRL/OCSP — basic chain validation only (accepted)
- DEC-CERT-004: SLH-DSA excluded from certificates — signature sizes impractical for X.509 (accepted)

## Phase 17: WASM Target (lupine-wasm)
**Status:** completed
**Commit:** `6353689`

New `lupine-wasm` crate with WebAssembly bindings via `wasm-bindgen`. Exposes `generateKeys`, `encrypt`, `decrypt`, `sign`, `verify` — thin wrappers around the easy API. `Keys` struct with camelCase JS getters returning `Uint8Array`. Browser RNG via `getrandom` js feature (`crypto.getRandomValues`). WASM build verified on `wasm32-unknown-unknown`. 10 native tests.

### Decision Log
- DEC-WASM-001: Thin wasm-bindgen wrapper over easy API — minimal surface, easy to audit (accepted)
- DEC-WASM-002: getrandom js feature for browser RNG, separate getrandom04 for rand 0.10 deps (accepted)
- DEC-WASM-003: Self-contained SK blob format (sk_len || sk || pk) to handle KitchenSink combiner requirement (accepted)
- DEC-WASM-004: Native #[test] tests prioritized over wasm-bindgen-test for CI reliability (accepted)

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

Main is sacred. All feature work happens in dedicated worktrees:
- Merge to main only after all Definition of Done criteria are met
- No active worktrees — all 18 phases complete
