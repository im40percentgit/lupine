# lupine-kem

Key Encapsulation Mechanism (KEM) implementations for the [Lupine](https://github.com/im40percentgit/lupine) post-quantum cryptography suite.

Wraps [ml-kem](https://crates.io/crates/ml-kem) (FIPS 203) with a consistent byte-oriented API and adds hybrid X25519+ML-KEM modes for defense-in-depth against classical and quantum adversaries.

## Algorithms

- ML-KEM-512 (NIST security level 1)
- ML-KEM-768 (NIST security level 3, recommended)
- ML-KEM-1024 (NIST security level 5)
- Hybrid X25519+ML-KEM-512/768/1024

## Usage

```toml
[dependencies]
lupine-kem = "0.1"
```

```rust
use lupine_kem::{KemAlgorithm, kem_keygen, encapsulate, decapsulate};

let algo = KemAlgorithm::MlKem768;
let (pk, sk) = kem_keygen(algo)?;
let (ciphertext, shared_secret) = encapsulate(algo, &pk)?;
let recovered = decapsulate(algo, &sk, &ciphertext)?;
assert_eq!(shared_secret.as_bytes(), recovered.as_bytes());
```

## Docs

[docs.rs/lupine-kem](https://docs.rs/lupine-kem)

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT) at your option.
