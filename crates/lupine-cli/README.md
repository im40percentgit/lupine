# lupine-cli

Command-line interface for the [Lupine](https://github.com/im40percentgit/lupine) post-quantum cryptography suite.

Provides `keygen`, `encapsulate`, `decapsulate`, `sign`, and `verify` subcommands for all 24 algorithm variants across ML-KEM, ML-DSA, SLH-DSA, and their hybrid classical+PQC counterparts.

## Install

```bash
cargo install lupine-cli
```

## Usage

```bash
# Generate an ML-KEM-768 keypair
lupine keygen --algorithm ml-kem-768 --out-pk pk.bin --out-sk sk.bin

# Encapsulate
lupine encapsulate --algorithm ml-kem-768 --pk pk.bin --out-ct ct.bin --out-ss ss.bin

# Decapsulate
lupine decapsulate --algorithm ml-kem-768 --sk sk.bin --ct ct.bin --out-ss ss.bin

# Sign
lupine sign --algorithm ml-dsa-65 --sk sk.bin --message msg.txt --out sig.bin

# Verify
lupine verify --algorithm ml-dsa-65 --vk vk.bin --message msg.txt --sig sig.bin
```

## Docs

[docs.rs/lupine-cli](https://docs.rs/lupine-cli)

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT) at your option.
