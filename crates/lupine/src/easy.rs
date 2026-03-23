//! High-level "easy" API for Lupine — Layer 1 of the canus-lupus stack.
//!
//! This module provides a simplified, defaults-first interface for the most
//! common cryptographic operations: key generation, encryption, decryption,
//! signing, and verification. Algorithm selection is hidden behind sensible
//! defaults; callers need no knowledge of ML-KEM or ML-DSA internals.
//!
//! # Defaults
//!
//! | Operation | Algorithm | Security Level |
//! |-----------|-----------|----------------|
//! | KEM       | Hybrid X25519 + ML-KEM-768  | NIST Level 3 |
//! | Signing   | Hybrid Ed25519 + ML-DSA-65  | NIST Level 3 |
//! | AEAD      | ChaCha20-Poly1305           | 256-bit key  |
//! | KDF       | HKDF-SHA-256                | —            |
//!
//! # Example
//!
//! ```rust
//! use lupine::easy;
//!
//! let alice = easy::generate_keys().unwrap();
//! let bob   = easy::generate_keys().unwrap();
//!
//! // Alice encrypts for Bob.
//! let sealed = easy::encrypt(&bob.kem_pk, b"hello post-quantum world").unwrap();
//! let plain  = easy::decrypt(&bob.kem_sk, &sealed).unwrap();
//! assert_eq!(plain, b"hello post-quantum world");
//!
//! // Alice signs; Bob verifies.
//! let sig = easy::sign(&alice.sign_sk, b"release v1.0").unwrap();
//! assert!(easy::verify(&alice.sign_pk, b"release v1.0", &sig).unwrap());
//! ```
//!
//! # Feature gate
//!
//! This module is compiled only when the `easy` feature is enabled (on by
//! default). Disabling it removes the AEAD/HKDF/SHA-2 dependencies and
//! preserves the `no_std` + raw-primitives usage path.
//!
//! @decision DEC-EASY-001
//! @title KEM-DEM construction with HKDF-SHA-256 + ChaCha20-Poly1305
//! @status accepted
//! @rationale The easy API must convert a KEM shared secret into authenticated
//!   encryption. HKDF-SHA-256 binds the derived AEAD key to the specific
//!   encapsulation (salt = KEM ciphertext bytes), preventing key reuse across
//!   different messages encrypted to the same recipient. ChaCha20-Poly1305 is
//!   chosen over AES-256-GCM for portability: it runs in constant time in
//!   software on all platforms including ARM without AES-NI, which matters for
//!   a library targeting embedded and server deployments alike.
//!
//! @decision DEC-EASY-002
//! @title Version-byte wire format
//! @status accepted
//! @rationale A single prefix byte (currently 0x01) encodes the full algorithm
//!   suite: KEM variant, AEAD cipher, and KDF. This lets the decoder select
//!   the correct algorithm without explicit length fields for the KEM ciphertext
//!   (the version byte implies the size). Future versions can introduce new
//!   byte values for algorithm agility without breaking v1 decoders.
//!
//! @decision DEC-EASY-003
//! @title AAD = version_byte || KEM_ciphertext
//! @status accepted
//! @rationale Including both the version byte and the full KEM ciphertext in
//!   the AEAD additional authenticated data prevents cross-protocol attacks
//!   (version byte) and ciphertext substitution attacks (KEM ciphertext
//!   binding). The AEAD tag covers the AAD so any tampering with these fields
//!   causes decryption to fail with an authentication error.

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;

use lupine_kem::hybrid::{
    generate_keypair as kem_generate_keypair, HybridKemCiphertext768, HybridKemPublicKey768,
    HybridKemSecretKey768,
};
use lupine_sign::hybrid::{
    generate_keypair as sign_generate_keypair, HybridSignature65, HybridSigningKey65,
    HybridVerifyingKey65,
};

// ── Wire format constants ─────────────────────────────────────────────────────

/// Version byte for the v1 sealed message format (X25519+ML-KEM-768 + ChaCha20-Poly1305).
const VERSION_V1: u8 = 0x01;

/// Byte length of the v1 hybrid KEM ciphertext:
/// 32 bytes (X25519 ephemeral public key) + 1088 bytes (ML-KEM-768 ciphertext).
const KEM_CT_LEN_V1: usize = 32 + 1088; // = 1120

/// Byte length of the ChaCha20-Poly1305 nonce.
const NONCE_LEN: usize = 12;

/// Byte length of the ChaCha20-Poly1305 authentication tag.
const TAG_LEN: usize = 16;

/// Minimum sealed message byte length:
/// version(1) + KEM ciphertext(1120) + nonce(12) + tag(16) = 1149.
const MIN_SEALED_LEN: usize = 1 + KEM_CT_LEN_V1 + NONCE_LEN + TAG_LEN;

/// HKDF info string binding the derived key to the canus-lupus v1 protocol
/// and the specific AEAD algorithm. Must not change for v1 compatibility.
const HKDF_INFO_V1: &[u8] = b"canus-lupus-v1-chacha20poly1305";

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the easy API.
///
/// The user-facing error type for all `lupine::easy` operations. Wraps
/// lower-level errors from the KEM, signature, and AEAD layers.
///
/// `lupine_core::Error` converts into `easy::Error` via [`From`] so that `?`
/// works seamlessly inside this module without boilerplate conversions.
#[derive(Debug)]
pub enum Error {
    /// A KEM or signature primitive failed (key generation, encapsulation,
    /// decapsulation, signing, or verification at the structural level).
    Crypto(lupine_core::Error),
    /// AEAD authentication failed: wrong key, tampered ciphertext, or
    /// tampered nonce. The plaintext is not returned.
    Aead,
    /// The sealed message is structurally invalid: too short, unknown version
    /// byte, or truncated AEAD payload.
    Format(&'static str),
}

impl From<lupine_core::Error> for Error {
    fn from(e: lupine_core::Error) -> Self {
        Error::Crypto(e)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Crypto(e) => write!(f, "crypto error: {e}"),
            Error::Aead => write!(f, "AEAD authentication failure"),
            Error::Format(msg) => write!(f, "format error: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Crypto(e) => Some(e),
            _ => None,
        }
    }
}

/// Convenience alias for `Result<T, easy::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

// ── Keypair ───────────────────────────────────────────────────────────────────

/// A complete keypair for both encryption and signing.
///
/// Generated by [`generate_keys`]. Contains four keys:
/// - `kem_sk` / `kem_pk`: hybrid X25519 + ML-KEM-768 decapsulation and
///   encapsulation keys, used with [`encrypt`] / [`decrypt`].
/// - `sign_sk` / `sign_pk`: hybrid Ed25519 + ML-DSA-65 signing and verifying
///   keys, used with [`sign`] / [`verify`].
///
/// # Security note
///
/// `kem_sk` and `sign_sk` contain secret key material. Both types implement
/// `ZeroizeOnDrop`, so their secret bytes are cleared when this struct drops.
pub struct Keypair {
    /// Hybrid KEM decapsulation (secret) key — X25519 + ML-KEM-768.
    pub kem_sk: HybridKemSecretKey768,
    /// Hybrid KEM encapsulation (public) key — X25519 + ML-KEM-768.
    pub kem_pk: HybridKemPublicKey768,
    /// Hybrid signing (secret) key — Ed25519 + ML-DSA-65.
    pub sign_sk: HybridSigningKey65,
    /// Hybrid verifying (public) key — Ed25519 + ML-DSA-65.
    pub sign_pk: HybridVerifyingKey65,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Generate a fresh keypair for encryption and signing.
///
/// Uses hybrid X25519 + ML-KEM-768 for KEM and hybrid Ed25519 + ML-DSA-65 for
/// signing — NIST Security Level 3 for both components.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if the OS RNG fails during key generation.
pub fn generate_keys() -> Result<Keypair> {
    // lupine-kem requires rand_core 0.6's CryptoRngCore; rand 0.8's OsRng satisfies it.
    let mut kem_rng = rand::rngs::OsRng;
    let (kem_sk, kem_pk) = kem_generate_keypair::<ml_kem::MlKem768>(&mut kem_rng)?;

    // lupine-sign requires rand_core 0.10's CryptoRng (RC).
    // rand 0.10 is aliased as `rand010` in Cargo.toml to coexist with rand 0.8 (workspace).
    // ThreadRng from rand 0.10 (via rand010::rng()) implements CryptoRng from rand_core 0.10.
    let mut sign_rng = rand010::rng();
    let (sign_sk, sign_pk) = sign_generate_keypair::<ml_dsa::MlDsa65>(&mut sign_rng)?;

    Ok(Keypair {
        kem_sk,
        kem_pk,
        sign_sk,
        sign_pk,
    })
}

/// Encrypt `plaintext` for `recipient_pk` using KEM-DEM hybrid encryption.
///
/// Implements the v1 construction:
/// 1. **KEM:** `encapsulate(recipient_pk)` → `(kem_ct, shared_secret)`
/// 2. **KDF:** `HKDF-SHA-256(ikm=shared_secret, salt=kem_ct_bytes, info="canus-lupus-v1-chacha20poly1305")` → 32-byte key
/// 3. **Nonce:** 12 random bytes from OS RNG
/// 4. **AEAD:** `ChaCha20-Poly1305(key, nonce, plaintext, aad=version||kem_ct_bytes)`
///
/// Returns a self-contained sealed message in the v1 wire format. Decrypt it
/// with [`decrypt`] and the matching secret key.
///
/// # Errors
///
/// - [`Error::Crypto`] if KEM encapsulation fails (RNG failure).
/// - [`Error::Aead`] if AEAD encryption fails (should not occur in practice).
pub fn encrypt(recipient_pk: &HybridKemPublicKey768, plaintext: &[u8]) -> Result<Vec<u8>> {
    // rand 0.8 OsRng satisfies lupine-kem's rand_core 0.6 CryptoRngCore bound.
    let mut rng = rand::rngs::OsRng;

    // Step 1: KEM — produce a fresh shared secret bound to recipient_pk.
    let (kem_ct, shared_secret) = recipient_pk.encapsulate(&mut rng)?;
    let kem_ct_bytes = kem_ct.to_bytes();
    debug_assert_eq!(
        kem_ct_bytes.len(),
        KEM_CT_LEN_V1,
        "KEM ciphertext size mismatch"
    );

    // Step 2: HKDF-SHA-256 — derive a 32-byte ChaCha20-Poly1305 key.
    // Using kem_ct_bytes as salt binds the AEAD key to this encapsulation,
    // so re-using the same recipient key with different messages produces
    // different AEAD keys.
    let hk = Hkdf::<Sha256>::new(Some(&kem_ct_bytes), shared_secret.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(HKDF_INFO_V1, &mut aead_key)
        .expect("HKDF expand with 32-byte output is always valid for SHA-256");

    // Step 3: random 12-byte nonce via rand 0.8.
    let nonce_bytes: [u8; NONCE_LEN] = rand::random();

    // Step 4: AAD = version byte || KEM ciphertext.
    // Both fields are covered by the AEAD tag; tampering either causes
    // decryption to fail.
    let mut aad = Vec::with_capacity(1 + KEM_CT_LEN_V1);
    aad.push(VERSION_V1);
    aad.extend_from_slice(&kem_ct_bytes);

    // Step 5: AEAD encryption.
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .expect("aead_key is always 32 bytes — length is a compile-time constant");
    let nonce = chacha20poly1305::Nonce::from(nonce_bytes);
    let aead_ct = cipher
        .encrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Aead)?;

    // Step 6: assemble wire format.
    // Layout: version(1) || kem_ct(1120) || nonce(12) || aead_ct+tag(N+16)
    let mut sealed = Vec::with_capacity(1 + KEM_CT_LEN_V1 + NONCE_LEN + aead_ct.len());
    sealed.push(VERSION_V1);
    sealed.extend_from_slice(&kem_ct_bytes);
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&aead_ct);

    Ok(sealed)
}

/// Decrypt a sealed message produced by [`encrypt`].
///
/// Parses the v1 wire format, recovers the shared secret by decapsulating
/// the embedded KEM ciphertext with `sk`, re-derives the AEAD key via
/// HKDF-SHA-256, and verifies + decrypts the payload.
///
/// # Errors
///
/// - [`Error::Format`] if the sealed message is too short or has an unknown
///   version byte.
/// - [`Error::Crypto`] if KEM decapsulation fails (wrong key or missing
///   ML-KEM public key bytes).
/// - [`Error::Aead`] if AEAD authentication fails (wrong key, tampered
///   ciphertext, tampered nonce, or truncated tag).
pub fn decrypt(sk: &HybridKemSecretKey768, sealed: &[u8]) -> Result<Vec<u8>> {
    // Validate outer structure.
    if sealed.len() < MIN_SEALED_LEN {
        return Err(Error::Format("sealed message too short"));
    }
    if sealed[0] != VERSION_V1 {
        return Err(Error::Format("unknown version byte"));
    }

    // Slice the wire fields.
    let kem_ct_bytes = &sealed[1..1 + KEM_CT_LEN_V1];
    let nonce_bytes = &sealed[1 + KEM_CT_LEN_V1..1 + KEM_CT_LEN_V1 + NONCE_LEN];
    let aead_ct = &sealed[1 + KEM_CT_LEN_V1 + NONCE_LEN..];

    if aead_ct.len() < TAG_LEN {
        return Err(Error::Format(
            "AEAD ciphertext too short (tag missing or truncated)",
        ));
    }

    // Recover the shared secret via KEM decapsulation.
    let kem_ct = HybridKemCiphertext768::from_bytes(kem_ct_bytes)?;
    let shared_secret = sk.decapsulate(&kem_ct)?;

    // Re-derive the AEAD key with identical HKDF inputs.
    let hk = Hkdf::<Sha256>::new(Some(kem_ct_bytes), shared_secret.as_bytes());
    let mut aead_key = [0u8; 32];
    hk.expand(HKDF_INFO_V1, &mut aead_key)
        .expect("HKDF expand with 32-byte output is always valid for SHA-256");

    // Reconstruct AAD to match what was used during encryption.
    let mut aad = Vec::with_capacity(1 + KEM_CT_LEN_V1);
    aad.push(VERSION_V1);
    aad.extend_from_slice(kem_ct_bytes);

    // AEAD decryption + authentication.
    let cipher = ChaCha20Poly1305::new_from_slice(&aead_key)
        .expect("aead_key is always 32 bytes — length is a compile-time constant");
    let nonce = chacha20poly1305::Nonce::from(
        <[u8; NONCE_LEN]>::try_from(nonce_bytes)
            .expect("nonce_bytes slice is always exactly NONCE_LEN bytes"),
    );
    let plaintext = cipher
        .decrypt(
            &nonce,
            chacha20poly1305::aead::Payload {
                msg: aead_ct,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Aead)?;

    Ok(plaintext)
}

/// Sign `data` with `sk` and return the serialized composite signature bytes.
///
/// Uses the hybrid Ed25519 + ML-DSA-65 signing key. Both components sign
/// `data` independently; the result is their length-prefixed concatenation.
/// Pass the returned bytes to [`verify`] with the matching verifying key.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if ML-DSA signing fails.
pub fn sign(sk: &HybridSigningKey65, data: &[u8]) -> Result<Vec<u8>> {
    let sig: HybridSignature65 = sk.sign(data)?;
    Ok(sig.to_bytes())
}

/// Verify `signature` over `data` using `pk`.
///
/// Returns `true` if the signature is valid for `data` under `pk`; `false` if
/// it is not (wrong key, tampered data, or tampered signature bytes).
///
/// Authentication failures return `Ok(false)`, not an error, so callers can
/// distinguish structural problems from cryptographic mismatches:
///
/// ```rust,no_run
/// # use lupine::easy;
/// # let kp = easy::generate_keys().unwrap();
/// # let sig = easy::sign(&kp.sign_sk, b"data").unwrap();
/// match easy::verify(&kp.sign_pk, b"data", &sig) {
///     Ok(true)  => println!("valid"),
///     Ok(false) => println!("invalid signature"),
///     Err(e)    => println!("malformed signature bytes: {e}"),
/// }
/// ```
///
/// # Errors
///
/// Returns [`Error::Crypto`] only if `signature` cannot be deserialized into a
/// structurally valid [`HybridSignature65`] (e.g. truncated bytes).
pub fn verify(pk: &HybridVerifyingKey65, data: &[u8], signature: &[u8]) -> Result<bool> {
    let sig = HybridSignature65::from_bytes(signature)?;
    match pk.verify(data, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Run `f` on a thread with a 32 MB stack.
    ///
    /// ML-DSA-65 operations allocate large on-stack intermediates in debug
    /// builds that exceed the default 8 MB thread stack, causing a stack
    /// overflow. All easy-API tests use this wrapper.
    fn with_large_stack<F: FnOnce() + Send + 'static>(f: F) {
        std::thread::Builder::new()
            .stack_size(32 * 1024 * 1024)
            .spawn(f)
            .expect("thread spawn failed")
            .join()
            .expect("thread panicked");
    }

    // ── generate_keys ─────────────────────────────────────────────────────────

    #[test]
    fn generate_keys_succeeds() {
        with_large_stack(|| {
            let _kp = generate_keys().expect("generate_keys must succeed");
        });
    }

    // ── encrypt / decrypt round-trip ──────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let plaintext = b"hello post-quantum world";
            let sealed = encrypt(&kp.kem_pk, plaintext).expect("encrypt");
            let recovered = decrypt(&kp.kem_sk, &sealed).expect("decrypt");
            assert_eq!(recovered.as_slice(), plaintext.as_slice());
        });
    }

    #[test]
    fn encrypt_decrypt_empty_plaintext() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let sealed = encrypt(&kp.kem_pk, b"").expect("encrypt empty");
            let recovered = decrypt(&kp.kem_sk, &sealed).expect("decrypt empty");
            assert!(recovered.is_empty());
        });
    }

    #[test]
    fn encrypt_produces_correct_wire_length() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let plaintext = b"test payload";
            let sealed = encrypt(&kp.kem_pk, plaintext).expect("encrypt");
            // v1: 1 (version) + 1120 (KEM ct) + 12 (nonce) + plaintext_len + 16 (tag)
            let expected = 1 + KEM_CT_LEN_V1 + NONCE_LEN + plaintext.len() + TAG_LEN;
            assert_eq!(sealed.len(), expected, "wire length must match v1 spec");
            assert_eq!(sealed[0], VERSION_V1, "first byte must be version 0x01");
        });
    }

    // ── error cases: tampered ciphertext ─────────────────────────────────────

    #[test]
    fn decrypt_tampered_aead_ciphertext_fails() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let sealed = encrypt(&kp.kem_pk, b"secret").expect("encrypt");

            let mut tampered = sealed.clone();
            // Flip a byte in the AEAD ciphertext region (after nonce).
            tampered[1 + KEM_CT_LEN_V1 + NONCE_LEN] ^= 0xFF;

            let result = decrypt(&kp.kem_sk, &tampered);
            assert!(
                matches!(result, Err(Error::Aead)),
                "tampered AEAD ciphertext must yield Err(Aead), got: {result:?}"
            );
        });
    }

    #[test]
    fn decrypt_tampered_nonce_fails() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let sealed = encrypt(&kp.kem_pk, b"secret").expect("encrypt");

            let mut tampered = sealed.clone();
            // Flip a byte inside the nonce region.
            tampered[1 + KEM_CT_LEN_V1] ^= 0xFF;

            let result = decrypt(&kp.kem_sk, &tampered);
            assert!(
                matches!(result, Err(Error::Aead)),
                "tampered nonce must yield Err(Aead), got: {result:?}"
            );
        });
    }

    // ── error cases: wrong key ────────────────────────────────────────────────

    #[test]
    fn decrypt_wrong_key_fails() {
        with_large_stack(|| {
            let alice = generate_keys().expect("keygen alice");
            let bob = generate_keys().expect("keygen bob");

            // Alice encrypts for herself; Bob tries to decrypt.
            let sealed = encrypt(&alice.kem_pk, b"for alice only").expect("encrypt");
            let result = decrypt(&bob.kem_sk, &sealed);
            // Wrong key → KEM produces a different shared secret → HKDF derives
            // the wrong AEAD key → authentication tag mismatch.
            assert!(result.is_err(), "decrypting with the wrong key must fail");
        });
    }

    // ── error cases: format errors ────────────────────────────────────────────

    #[test]
    fn decrypt_truncated_sealed_fails() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let sealed = encrypt(&kp.kem_pk, b"hello").expect("encrypt");

            let truncated = &sealed[..MIN_SEALED_LEN - 1];
            let result = decrypt(&kp.kem_sk, truncated);
            assert!(
                matches!(result, Err(Error::Format(_))),
                "truncated sealed must yield Err(Format), got: {result:?}"
            );
        });
    }

    #[test]
    fn decrypt_unknown_version_fails() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let mut sealed = encrypt(&kp.kem_pk, b"hello").expect("encrypt");

            sealed[0] = 0xFF; // unknown version byte
            let result = decrypt(&kp.kem_sk, &sealed);
            assert!(
                matches!(result, Err(Error::Format(_))),
                "unknown version must yield Err(Format), got: {result:?}"
            );
        });
    }

    // ── sign / verify round-trip ──────────────────────────────────────────────

    #[test]
    fn sign_verify_roundtrip() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let data = b"lupine easy API sign/verify test";
            let sig = sign(&kp.sign_sk, data).expect("sign");
            let ok = verify(&kp.sign_pk, data, &sig).expect("verify");
            assert!(ok, "valid signature must verify as true");
        });
    }

    #[test]
    fn verify_wrong_key_returns_false() {
        with_large_stack(|| {
            let alice = generate_keys().expect("keygen alice");
            let bob = generate_keys().expect("keygen bob");

            let data = b"signed by alice";
            let sig = sign(&alice.sign_sk, data).expect("sign");

            let ok = verify(&bob.sign_pk, data, &sig)
                .expect("verify must not return Err for a structurally valid signature");
            assert!(!ok, "alice's signature must not verify with bob's key");
        });
    }

    #[test]
    fn verify_tampered_data_returns_false() {
        with_large_stack(|| {
            let kp = generate_keys().expect("keygen");
            let data = b"original data";
            let sig = sign(&kp.sign_sk, data).expect("sign");

            let ok = verify(&kp.sign_pk, b"tampered data", &sig).expect("verify");
            assert!(!ok, "signature must not verify over modified data");
        });
    }
}
