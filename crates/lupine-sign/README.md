# lupine-sign

Digital signature implementations for the [Lupine](https://github.com/im40percentgit/lupine) post-quantum cryptography suite.

Wraps [ml-dsa](https://crates.io/crates/ml-dsa) (FIPS 204) and [slh-dsa](https://crates.io/crates/slh-dsa) (FIPS 205) with a consistent API and adds hybrid Ed25519+ML-DSA modes for defense-in-depth.

## Algorithms

- ML-DSA-44/65/87 (FIPS 204 — lattice-based, fast)
- SLH-DSA (12 parameter sets, FIPS 205 — hash-based, conservative)
- Hybrid Ed25519+ML-DSA-44/65/87

## Usage

```toml
[dependencies]
lupine-sign = "0.1"
```

```rust
use lupine_sign::{SignAlgorithm, sign_keygen, sign, verify};

let algo = SignAlgorithm::MlDsa65;
let (vk, sk) = sign_keygen(algo)?;
let sig = sign(algo, &sk, b"hello")?;
verify(algo, &vk, b"hello", &sig)?;
```

## Docs

[docs.rs/lupine-sign](https://docs.rs/lupine-sign)

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT) at your option.
