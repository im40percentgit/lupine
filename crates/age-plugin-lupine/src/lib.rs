//! Post-quantum age plugin using hybrid X25519+ML-KEM-768.
//!
//! This crate provides the cryptographic core for an age-compatible plugin
//! that wraps and unwraps age file keys using the hybrid KEM from
//! [`lupine_kem::hybrid`]. It is **not** a full implementation of the age
//! plugin protocol — it focuses on key generation, Bech32 key encoding,
//! and file-key wrapping/unwrapping.
//!
//! # Key format
//!
//! - **Recipient** (public key): `age1lupine1<bech32_encoded_public_key>`
//! - **Identity** (secret key): `AGE-PLUGIN-LUPINE-1<BECH32_ENCODED_SECRET_KEY>`
//!
//! # File key wrapping
//!
//! The 16-byte age file key is wrapped using:
//! 1. Hybrid KEM encapsulation to produce a shared secret
//! 2. HKDF-SHA-256 key derivation (salt = ciphertext, info = `b"age-plugin-lupine"`)
//! 3. ChaCha20-Poly1305 encryption of the file key with a zero nonce
//!    (safe because the wrap key is unique per KEM encapsulation)
//!
//! @decision DEC-AGE-PLUGIN-001
//! @title Bech32 encoding without checksum for large PQC keys
//! @status accepted
//! @rationale Hybrid X25519+ML-KEM-768 public keys are 1216 bytes, which
//!   encodes to ~1946 bech32 characters — far exceeding the Bech32m CODE_LENGTH
//!   of 1023 where error-detection guarantees hold. We use bech32 `NoChecksum`
//!   encoding for the HRP-prefixed base32 format while accepting that checksum
//!   error detection is not available at this length. This matches how age
//!   itself treats bech32: primarily as a human-readable encoding format.
//!
//! @decision DEC-AGE-PLUGIN-002
//! @title Identity encoding includes public key bytes for decapsulation
//! @status accepted
//! @rationale `HybridKemSecretKey::from_bytes` produces a key with empty
//!   `mlkem_pk_bytes`, which is required for KitchenSink combining during
//!   decapsulation. The identity encodes `sk_bytes || pk_bytes` so that
//!   decoding can restore the full secret key with `set_mlkem_pk_bytes`.

pub mod keys;
pub mod wrap;

/// Re-export the hybrid KEM generate function for use by the binary.
pub use lupine_kem::hybrid::generate_keypair;
