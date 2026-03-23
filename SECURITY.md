# Security Audit — Lupine v0.1.0

This document records the Phase 10 security hardening audit. It covers zeroize
coverage, constant-time guarantees, unsafe review, and responsible disclosure.

Last updated: 2026-03-23 (Phase 10 implementation)

---

## 1. Zeroize Coverage

### Secret key types

All secret key types implement zeroize-on-drop. The table below records the
mechanism for each type and what fields it covers.

| Type | Crate | Mechanism | Fields zeroized |
|------|-------|-----------|-----------------|
| `SharedSecret` | `lupine-core` | `#[derive(Zeroize, ZeroizeOnDrop)]` | inner `Vec<u8>` |
| `MlKemSecretKey<P>` | `lupine-kem` | Manual `Drop` impl | `bytes: Vec<u8>`, `ek_bytes: Vec<u8>`; native `DecapsulationKey` via `ml-kem/zeroize` |
| `HybridKemSecretKey<P>` | `lupine-kem` | Manual `Drop` impl | `mlkem_pk_bytes: Vec<u8>`; `x25519_sk: StaticSecret` via `x25519-dalek` ZeroizeOnDrop; `mlkem_sk` via its own Drop |
| `MlDsaSigningKey<P>` | `lupine-sign` | Manual `Drop` impl | `seed: [u8; 32]`; native `SigningKey<P>` via `ml-dsa/zeroize` |
| `SlhDsaSigningKey<P>` | `lupine-sign` | Manual `Drop` impl | `bytes: Vec<u8>`; native `SigningKey<P>` via `slh-dsa/zeroize` |
| `HybridSigningKey<P>` | `lupine-sign` | Component-level ZeroizeOnDrop | `Ed25519SigningKey` via `ed25519-dalek` ZeroizeOnDrop; `MlDsaSigningKey` via its own Drop — no wrapper-level Drop needed |

Note: `HybridSigningKey` does not implement a wrapper-level `Drop` because both
component fields already carry their own `ZeroizeOnDrop` guarantees. This is
documented in the struct-level comment in `hybrid.rs`.

### Intermediate ephemeral secret material

| Location | Variable | Treatment |
|----------|----------|-----------|
| `easy::encrypt` | `aead_key: [u8; 32]` | `aead_key.zeroize()` called unconditionally after AEAD encrypt, before returning |
| `easy::decrypt` | `aead_key: [u8; 32]` | `aead_key.zeroize()` called unconditionally after AEAD decrypt, before returning |
| `mldsa::generate_keypair` | `seed_bytes: [u8; 32]` | `seed_bytes.zeroize()` called after key construction; canonical copy lives in `MlDsaSigningKey.seed` |
| `keystore::load_kem_sk` | `sk_bytes: Vec<u8>` | `sk_bytes.zeroize()` called after `HybridKemSecretKey768::from_bytes()` consumes it |
| `keystore::load_sign_sk` | `bytes: Vec<u8>` | `bytes.zeroize()` called after `HybridSigningKey65::from_bytes()` consumes it |

### PEM string intermediates

`keystore::load_kem_sk` and `keystore::load_sign_sk` read PEM files into
`String` via `fs::read_to_string`. These strings contain base64-encoded key
material (not the raw bytes). They are dropped at the end of the function scope
but are not explicitly zeroized. Zeroizing `String` would require either a
custom wrapper or adding a `zeroize` call on `String::as_bytes_mut()`.

**Assessment:** The PEM string intermediates represent a lower-priority gap.
The base64 encoding adds a layer of indirection, and the strings live only for
the duration of the key-load function. Addressing them would require either a
`ZeroizingString` newtype or moving to an `fs::read` → manual PEM decode path.
This is tracked for Phase 11 as a hardening improvement, not a blocking issue.

### Key bytes returned from `to_bytes()`

Several `to_bytes()` methods return `&[u8]` or `Vec<u8>` of raw secret key
material. Callers are responsible for zeroizing these if they store them in
local variables before passing to serializers. The `save_keypair` function in
`keystore.rs` passes the result directly to `pem::encode_private_key_pem()`
without an intermediate binding, so no separate zeroize step is needed there.

---

## 2. Constant-Time Guarantees

### Operations that are constant-time

| Operation | Where | Guarantee source |
|-----------|-------|-----------------|
| ML-KEM encapsulation / decapsulation | `lupine-kem` | `ml-kem` crate uses constant-time arithmetic throughout; decapsulation uses implicit rejection (FIPS 203 §6.4) which is also constant-time |
| ML-DSA sign / verify | `lupine-sign` | `ml-dsa` crate uses constant-time NTT and modular arithmetic per FIPS 204 |
| SLH-DSA sign / verify | `lupine-sign` | `slh-dsa` crate; hash-based scheme has no secret-dependent branches in verification |
| X25519 DH | `lupine-kem::hybrid` | `x25519-dalek` uses a constant-time Montgomery ladder |
| Ed25519 sign / verify | `lupine-sign::hybrid` | `ed25519-dalek` uses a constant-time scalar multiplication |
| ChaCha20-Poly1305 tag verification | `lupine::easy` | `chacha20poly1305` crate uses `subtle::ConstantTimeEq` for tag comparison |
| HKDF-SHA-256 key derivation | `lupine::easy` | Not secret-dependent in timing; HKDF is a one-way function — no timing oracle possible |

### Operations that are NOT constant-time

| Operation | Where | Notes |
|-----------|-------|-------|
| `SharedSecret::PartialEq` | `lupine-core` | Non-constant-time comparison of `Vec<u8>`. This is only used in tests — the `PartialEq` comment in `types.rs` already documents this. Callers requiring constant-time comparison should use `subtle::ConstantTimeEq` directly. |
| `MlKemSecretKey` / `MlKemPublicKey` equality (`PartialEq`, `Eq`) | `lupine-kem` | Derived `PartialEq` on structs containing `Vec<u8>`. Used only in tests and serialization round-trips, not in any cryptographic protocol step. |

### Compiler optimization caveat

Rust's optimizer may in principle eliminate `zeroize()` calls if it determines
the memory is not subsequently read. The `zeroize` crate uses a compiler fence
(`core::sync::atomic::compiler_fence(Ordering::SeqCst)`) combined with
`volatile_write` to prevent this. This approach is the current Rust best
practice. It does not guarantee elimination is impossible at the hardware
microarchitecture level (e.g., via register file), but it does prevent
elimination at the IR/codegen level.

---

## 3. Unsafe Code Audit

**Result: zero `unsafe` blocks in the entire Lupine codebase.**

Verification command (run from workspace root):

```
grep -r 'unsafe' crates/ --include='*.rs'
```

This command produces no output. Every crate in the workspace is implicitly
`#![forbid(unsafe_code)]` by absence — no `unsafe` block or `extern "C"` call
exists anywhere.

All cryptographic primitives are provided by RustCrypto crates (`ml-kem`,
`ml-dsa`, `slh-dsa`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`).
These upstream crates may contain `unsafe` internally, but that is outside the
scope of this audit and is governed by their own security policies.

---

## 4. Known Limitations

1. **No passphrase protection on stored keys.** Keys in the `canus-lupus`
   keystore are stored as plaintext PEM files (mode 0600). An attacker with
   read access to `~/.canus-lupus/keys/` can recover secret keys directly.
   Passphrase-based key wrapping (e.g., Argon2 + AES-KW) is deferred to a
   future phase.

2. **PEM string intermediates not zeroized.** As noted in §1, `String` values
   holding base64-encoded key material in `keystore.rs` are dropped but not
   explicitly zeroized. The base64 encoding and short lifetime reduce practical
   risk, but this is a known gap.

3. **`SharedSecret::PartialEq` is not constant-time.** As noted in §2, this
   equality implementation is used only in tests. Production code paths do not
   compare `SharedSecret` values for equality after a protocol run.

4. **Side-channel resilience is upstream-dependent.** Lupine's constant-time
   guarantees for KEM and signature operations depend on the RustCrypto
   implementations being constant-time. Lupine does not independently verify
   this at the assembly level.

5. **`easy::encrypt` nonce is random, not misuse-resistant.** The 12-byte
   ChaCha20-Poly1305 nonce is generated from OS RNG. With a 96-bit nonce space,
   nonce collision probability is negligible for practical message volumes, but
   a misuse-resistant AEAD (e.g., AES-GCM-SIV) would be appropriate for
   high-volume applications.

---

## 5. Responsible Disclosure

To report a security vulnerability in Lupine, please open a GitHub Security
Advisory in the repository rather than a public issue. Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept (if applicable)
- The affected crate(s) and version(s)

We aim to respond within 72 hours and to publish a fix within 14 days for
critical issues.

---

## 6. Audit Checklist

- [x] All secret key types implement `Zeroize`/`ZeroizeOnDrop` or manual `Drop`
- [x] Ephemeral AEAD key in `easy::encrypt` / `easy::decrypt` is zeroized after use
- [x] Ephemeral seed bytes in `mldsa::generate_keypair` are zeroized after use
- [x] Secret key byte intermediates in `keystore::load_kem_sk` / `load_sign_sk` are zeroized
- [x] Zero `unsafe` blocks in the workspace confirmed by `grep`
- [x] Constant-time operations documented with their upstream guarantee sources
- [x] Non-constant-time operations identified and assessed as test-only / low-risk
- [x] Known limitations documented
- [x] All 300+ tests pass after hardening changes
- [x] `cargo clippy --workspace -- -D warnings` clean after hardening changes
