# lupine-core

Core types, traits, and error handling for the [Lupine](https://github.com/im40percentgit/lupine) post-quantum cryptography suite.

This crate provides the foundational building blocks used by all other Lupine crates:
- `Error` — unified error type
- `SecurityLevel` — five-level security taxonomy (L1 through L5)
- `KemAlgorithm` / `SignAlgorithm` — algorithm enumerations covering all FIPS 203/204/205 variants
- `SharedSecret` — opaque zeroize-on-drop wrapper for KEM shared secrets

## Usage

```toml
[dependencies]
lupine-core = "0.1"
```

Most users should depend on the top-level [`lupine`](https://crates.io/crates/lupine) crate instead.

## Docs

[docs.rs/lupine-core](https://docs.rs/lupine-core)

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT) at your option.
