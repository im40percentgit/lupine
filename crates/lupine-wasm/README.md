# lupine-wasm

WebAssembly bindings for [Lupine](https://github.com/im40percentgit/lupine) post-quantum cryptography.

Exposes key generation, hybrid encryption (X25519 + ML-KEM-768 + ChaCha20-Poly1305), and hybrid signing (Ed25519 + ML-DSA-65) to JavaScript via `wasm-bindgen`.

## Usage

```javascript
import init, { generateKeys, encrypt, decrypt, sign, verify } from '@lupine/pqc';

await init();

// Generate a PQC keypair
const keys = generateKeys();

// Encrypt and decrypt
const plaintext = new TextEncoder().encode("secret message");
const sealed = encrypt(keys.kemPublicKey, plaintext);
const recovered = decrypt(keys.kemSecretKey, sealed);
console.log(new TextDecoder().decode(recovered)); // "secret message"

// Sign and verify
const message = new TextEncoder().encode("release v1.0");
const signature = sign(keys.signSecretKey, message);
const valid = verify(keys.signPublicKey, message, signature);
console.assert(valid === true);
```

## API

| Function | Description |
|----------|-------------|
| `generateKeys()` | Generate a hybrid PQC keypair (KEM + signing) |
| `encrypt(kemPublicKey, plaintext)` | Encrypt bytes for a recipient |
| `decrypt(kemSecretKey, sealed)` | Decrypt sealed bytes |
| `sign(signingKey, message)` | Sign a message |
| `verify(verifyingKey, message, signature)` | Verify a signature |

The `Keys` object returned by `generateKeys()` has four `Uint8Array` properties:
- `kemPublicKey` / `kemSecretKey` -- hybrid X25519 + ML-KEM-768
- `signPublicKey` / `signSecretKey` -- hybrid Ed25519 + ML-DSA-65

## Building

```bash
# Native tests (no wasm toolchain required)
cargo test -p lupine-wasm

# WASM build
rustup target add wasm32-unknown-unknown
cargo build -p lupine-wasm --target wasm32-unknown-unknown

# Full wasm-pack build (produces npm package)
wasm-pack build crates/lupine-wasm --target web
```

## License

MIT OR Apache-2.0
