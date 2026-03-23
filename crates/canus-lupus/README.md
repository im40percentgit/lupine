# canus-lupus

Post-quantum Swiss Army Knife CLI — a high-level command-line tool built on the [Lupine](https://github.com/im40percentgit/lupine) PQC suite.

`canus-lupus` provides a keystore-backed workflow for generating, storing, and using post-quantum keys without managing raw key bytes manually.

## Install

```bash
cargo install canus-lupus
```

## Usage

```bash
# Generate and store a keypair in the local keystore (~/.canus-lupus/)
canus-lupus keygen --name alice --algorithm ml-kem-768

# Encrypt a file to a recipient's public key
canus-lupus encrypt --recipient alice --input plaintext.txt --output ciphertext.bin

# Decrypt
canus-lupus decrypt --key alice --input ciphertext.bin --output plaintext.txt

# Sign a file
canus-lupus sign --key alice --input document.txt --output document.sig

# Verify a signature
canus-lupus verify --key alice --input document.txt --sig document.sig
```

## Docs

[docs.rs/canus-lupus](https://docs.rs/canus-lupus)

## License

Licensed under either of [Apache-2.0](../../LICENSE-APACHE) or [MIT](../../LICENSE-MIT) at your option.
