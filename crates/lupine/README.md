# lupine-pqc

Post-quantum cryptography for Rust — FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) with hybrid classical+PQC modes.

This is the top-level facade crate. It re-exports [`lupine-core`], [`lupine-kem`], [`lupine-sign`], and [`lupine-serial`], and provides the high-level `easy` API for common encrypt/decrypt/sign/verify workflows.

## Quick Start

```toml
[dependencies]
lupine-pqc = "0.1"
```

```rust
use lupine::easy;

// High-level API: hybrid PQC encrypt/decrypt
let (pk, sk) = easy::generate_kem_keypair()?;
let ciphertext = easy::encrypt(&pk, b"hello post-quantum world")?;
let plaintext = easy::decrypt(&sk, &ciphertext)?;

// High-level API: hybrid PQC sign/verify
let (vk, signing_key) = easy::generate_sign_keypair()?;
let sig = easy::sign(&signing_key, b"message")?;
easy::verify(&vk, b"message", &sig)?;
```

## Algorithm Support

- **KEM:** ML-KEM-512/768/1024 (FIPS 203), hybrid X25519+ML-KEM
- **Signatures:** ML-DSA-44/65/87 (FIPS 204), SLH-DSA (12 param sets, FIPS 205), hybrid Ed25519+ML-DSA
- **Serialization:** DER, PEM, SPKI with NIST OIDs

## Security

See [SECURITY.md](https://github.com/im40percentgit/lupine/blob/main/SECURITY.md).

## Docs

[docs.rs/lupine-pqc](https://docs.rs/lupine-pqc)

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT) at your option.
