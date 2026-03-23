# lupine-serial

DER, PEM, and SPKI serialization for the [Lupine](https://github.com/im40percentgit/lupine) post-quantum cryptography suite.

Serializes ML-KEM, ML-DSA, and SLH-DSA public and secret keys using NIST-assigned OIDs and standard ASN.1/DER/PEM encodings compatible with existing PKI tooling.

## Features

- DER encoding/decoding for all key types
- PEM (RFC 7468) encoding/decoding
- SubjectPublicKeyInfo (SPKI) format for public keys
- Composite public key encoding for hybrid schemes

## Usage

```toml
[dependencies]
lupine-serial = "0.1"
```

```rust
use lupine_serial::{encode_public_key_pem, decode_public_key_pem};
use lupine_kem::KemAlgorithm;

let (pk, _sk) = lupine_kem::kem_keygen(KemAlgorithm::MlKem768)?;
let pem = encode_public_key_pem(KemAlgorithm::MlKem768, &pk)?;
let recovered = decode_public_key_pem(&pem)?;
```

## Docs

[docs.rs/lupine-serial](https://docs.rs/lupine-serial)

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT) at your option.
