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

## Quick Start — Library

Add to `Cargo.toml`:

```toml
[dependencies]
lupine-pqc = "0.1"
```

```rust
use lupine::easy;

// Generate hybrid PQC keypairs (X25519+ML-KEM-768 + Ed25519+ML-DSA-65)
let keys = easy::generate_keys()?;

// Encrypt a message
let sealed = easy::encrypt(&keys.kem_pk, b"hello post-quantum world")?;

// Decrypt it
let plaintext = easy::decrypt(&keys.kem_sk, &sealed)?;

// Sign data
let signature = easy::sign(&keys.sign_sk, b"important document")?;

// Verify signature
let valid = easy::verify(&keys.sign_pk, b"important document", &signature)?;
```

For lower-level control (specific algorithms, parameter sets), use `lupine_kem` and `lupine_sign` directly. See the [examples](crates/lupine/examples/).

## Quick Start — CLI (canus-lupus)

```bash
# Install to ~/.cargo/bin (available everywhere)
cargo install --path crates/canus-lupus

# Or run without installing
cargo run -p canus-lupus -- keygen

# Generate a keypair
canus-lupus keygen

# Encrypt a file
canus-lupus encrypt secret.txt
canus-lupus decrypt secret.txt.enc

# Sign and verify
canus-lupus sign release.tar.gz
canus-lupus verify release.tar.gz

# Manage keys
canus-lupus keys list
canus-lupus keys export --name default

# Encrypted secret vault
canus-lupus vault init
canus-lupus vault set api/openai "sk-..."
canus-lupus vault get api/openai
canus-lupus vault list
canus-lupus vault rm api/openai
```

Keys are stored in `~/.canus-lupus/keys/`. Override with `CANUS_LUPUS_HOME`.

## Quick Start — Expert CLI (lupine-cli)

For direct access to all 24 algorithm variants:

```bash
# Install to ~/.cargo/bin
cargo install --path crates/lupine-cli

# ML-KEM-768 key exchange
lupine-cli keygen --algorithm ml-kem-768
lupine-cli encapsulate --algorithm ml-kem-768 --pub-key ml-kem-768.pub
lupine-cli decapsulate --algorithm ml-kem-768 --sec-key ml-kem-768.sec --ciphertext ct.bin

# Hybrid Ed25519+ML-DSA-65 signing
lupine-cli keygen --algorithm hybrid-ml-dsa-65
lupine-cli sign --algorithm hybrid-ml-dsa-65 --sec-key hybrid-ml-dsa-65.sec < message.txt
lupine-cli verify --algorithm hybrid-ml-dsa-65 --pub-key hybrid-ml-dsa-65.pub --signature sig.bin < message.txt
```

## Running Examples

```bash
cargo run --example encrypt_file    # KEM-DEM encrypt/decrypt with tamper detection
cargo run --example sign_verify     # Hybrid sign/verify with wrong-key checks
cargo run --example kem_raw         # Raw ML-KEM-768 API with key size comparison
```

## Development

```bash
cargo test --workspace                   # Run all 343 tests
cargo clippy --workspace -- -D warnings  # Lint
cargo fmt --check                        # Format check
cargo doc --no-deps --workspace          # Build docs
cargo bench -p lupine-kem               # KEM benchmarks
cargo bench -p lupine-sign              # Signature benchmarks
```

See [BENCHMARKS.md](BENCHMARKS.md) for performance data.

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
