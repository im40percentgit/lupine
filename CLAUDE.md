# Lupine

Post-quantum cryptography library implementing FIPS 203/204/205 with hybrid classical+PQC modes.

## Stack

- Language: Rust (edition 2021, MSRV 1.85)
- Package manager: Cargo
- Test framework: built-in `#[test]` + proptest (property-based) + criterion (benchmarks)
- License: MIT OR Apache-2.0

## Commands

```bash
cargo check                              # Typecheck
cargo build                              # Build (debug)
cargo build --release                    # Build (release)
cargo test --workspace                   # Run all 296 tests
cargo clippy --workspace -- -D warnings  # Lint
cargo bench -p lupine-kem                # KEM benchmarks
cargo bench -p lupine-sign               # Signature benchmarks
cargo fmt --check                        # Format check
```

## Architecture

Workspace with 6 crates:

| Crate | Purpose |
|-------|---------|
| `lupine-core` | Core types, traits, error handling, algorithm enums, SecurityLevel taxonomy |
| `lupine-kem` | ML-KEM (FIPS 203) wrappers + hybrid X25519+ML-KEM with KitchenSink combiner |
| `lupine-sign` | ML-DSA (FIPS 204) + SLH-DSA (FIPS 205) wrappers + hybrid Ed25519+ML-DSA |
| `lupine-serial` | DER/PEM/SPKI/composite serialization with NIST OIDs |
| `lupine-cli` | CLI interface (keygen, encapsulate, decapsulate, sign, verify) for all 24 algorithm variants |
| `lupine` | Top-level facade re-exporting all constituent crates |

Additional directories:
- `fuzz/` — Cargo-fuzz harnesses (DER decode, PEM parse, SPKI decode)
- `MASTER_PLAN.md` — Project roadmap (phases 1-11)
- `BENCHMARKS.md` — Performance data and methodology

## Conventions

- All public types implement `Zeroize` for secret material
- Hybrid schemes combine classical + PQC (defense-in-depth)
- Algorithm variants are enumerated, not generic parameters
- Error types are crate-specific, converting to `lupine_core::Error` at boundaries
- Tests use proptest for property-based testing and embedded KATs for correctness

## Citadel Harness

This project uses the [Citadel](https://github.com/SethGammon/Citadel) agent orchestration harness. Configuration is in `.claude/harness.json`.
