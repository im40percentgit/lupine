# Lupine

Post-quantum cryptography library for Rust implementing FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA) with hybrid classical+PQC modes and DER/PEM serialization.

## Crates

| Crate | Description | crates.io |
|-------|-------------|-----------|
| [`lupine`](crates/lupine/) | Top-level facade — re-exports all constituent crates | [![crates.io](https://img.shields.io/crates/v/lupine.svg)](https://crates.io/crates/lupine) |
| [`lupine-core`](crates/lupine-core/) | Core types, traits, error handling, SecurityLevel taxonomy | [![crates.io](https://img.shields.io/crates/v/lupine-core.svg)](https://crates.io/crates/lupine-core) |
| [`lupine-kem`](crates/lupine-kem/) | ML-KEM (FIPS 203) + hybrid X25519+ML-KEM | [![crates.io](https://img.shields.io/crates/v/lupine-kem.svg)](https://crates.io/crates/lupine-kem) |
| [`lupine-sign`](crates/lupine-sign/) | ML-DSA (FIPS 204), SLH-DSA (FIPS 205) + hybrid Ed25519+ML-DSA | [![crates.io](https://img.shields.io/crates/v/lupine-sign.svg)](https://crates.io/crates/lupine-sign) |
| [`lupine-serial`](crates/lupine-serial/) | DER/PEM/SPKI serialization with NIST OIDs | [![crates.io](https://img.shields.io/crates/v/lupine-serial.svg)](https://crates.io/crates/lupine-serial) |
| [`lupine-cli`](crates/lupine-cli/) | CLI for all 24 algorithm variants | [![crates.io](https://img.shields.io/crates/v/lupine-cli.svg)](https://crates.io/crates/lupine-cli) |
| [`canus-lupus`](crates/canus-lupus/) | High-level CLI with keystore management | [![crates.io](https://img.shields.io/crates/v/canus-lupus.svg)](https://crates.io/crates/canus-lupus) |

## Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
lupine = "0.1"
```

```rust
use lupine::easy;

// Generate a hybrid PQC keypair (X25519 + ML-KEM-768)
let (public_key, secret_key) = easy::generate_kem_keypair()?;

// Encrypt a message
let ciphertext = easy::encrypt(&public_key, b"hello post-quantum world")?;

// Decrypt it
let plaintext = easy::decrypt(&secret_key, &ciphertext)?;
```

## Algorithm Support

- **KEM:** ML-KEM-512, ML-KEM-768, ML-KEM-1024 (FIPS 203) + hybrid X25519+ML-KEM
- **Signatures:** ML-DSA-44/65/87 (FIPS 204), SLH-DSA (12 parameter sets, FIPS 205) + hybrid Ed25519+ML-DSA

## Security

See [SECURITY.md](SECURITY.md) for the security policy and vulnerability reporting.

## License

Licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
