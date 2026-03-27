//! File key wrapping and unwrapping using hybrid X25519+ML-KEM-768.
//!
//! The age protocol gives plugins a 16-byte file key to wrap per-recipient.
//! This module wraps/unwraps that file key using:
//!
//! 1. Hybrid KEM encapsulation → shared secret
//! 2. HKDF-SHA-256 key derivation → 32-byte wrap key
//! 3. ChaCha20-Poly1305 AEAD encryption of the file key
//!
//! @decision DEC-AGE-WRAP-001
//! @title Zero nonce safe due to unique-per-encapsulation wrap key
//! @status accepted
//! @rationale Each wrap operation performs a fresh KEM encapsulation, producing
//!   a unique shared secret and therefore a unique HKDF-derived wrap key. Since
//!   the key is never reused, a zero nonce is safe — the (key, nonce) pair is
//!   unique for every encryption. This avoids nonce management complexity.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use lupine_kem::hybrid::{HybridKemCiphertext768, HybridKemPublicKey768, HybridKemSecretKey768};
use rand::rngs::OsRng;
use sha2::Sha256;
use zeroize::Zeroize;

/// HKDF info string binding the derived key to this plugin.
const HKDF_INFO: &[u8] = b"age-plugin-lupine";

/// Zero nonce — safe because the wrap key is unique per KEM encapsulation.
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// Wrap (encrypt) a 16-byte age file key for a recipient.
///
/// Returns `(kem_ciphertext_bytes, encrypted_file_key)` where:
/// - `kem_ciphertext_bytes`: the hybrid KEM ciphertext (1120 bytes)
/// - `encrypted_file_key`: ChaCha20-Poly1305 ciphertext (32 bytes = 16 plaintext + 16 tag)
///
/// # Errors
///
/// Returns an error if KEM encapsulation or AEAD encryption fails.
pub fn wrap_file_key(
    file_key: &[u8; 16],
    recipient_pk: &HybridKemPublicKey768,
) -> Result<(Vec<u8>, Vec<u8>)> {
    // 1. KEM encapsulate
    let (ct, shared_secret) = recipient_pk
        .encapsulate(&mut OsRng)
        .context("KEM encapsulation failed")?;
    let ct_bytes = ct.to_bytes();

    // 2. HKDF-SHA-256: salt = ciphertext, IKM = shared secret
    let hkdf = Hkdf::<Sha256>::new(Some(&ct_bytes), shared_secret.as_bytes());
    let mut wrap_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut wrap_key)
        .expect("32-byte output is valid for HKDF-SHA-256");

    // 3. ChaCha20-Poly1305 encrypt the file key
    let cipher = ChaCha20Poly1305::new((&wrap_key).into());
    let nonce = Nonce::from(ZERO_NONCE);
    let encrypted_file_key = cipher
        .encrypt(&nonce, file_key.as_ref())
        .map_err(|_| anyhow::anyhow!("AEAD encryption failed"))?;

    // Zeroize the wrap key
    wrap_key.zeroize();

    Ok((ct_bytes, encrypted_file_key))
}

/// Unwrap (decrypt) a 16-byte age file key using an identity's secret key.
///
/// # Errors
///
/// Returns an error if:
/// - The KEM ciphertext bytes are malformed
/// - KEM decapsulation fails
/// - AEAD decryption fails (wrong key or tampered ciphertext)
pub fn unwrap_file_key(
    kem_ciphertext: &[u8],
    encrypted_file_key: &[u8],
    identity_sk: &HybridKemSecretKey768,
) -> Result<[u8; 16]> {
    // 1. Deserialize the KEM ciphertext
    let ct = HybridKemCiphertext768::from_bytes(kem_ciphertext)
        .context("invalid KEM ciphertext")?;

    // 2. KEM decapsulate
    let shared_secret = identity_sk
        .decapsulate(&ct)
        .context("KEM decapsulation failed")?;

    // 3. HKDF-SHA-256: same derivation as wrap
    let hkdf = Hkdf::<Sha256>::new(Some(kem_ciphertext), shared_secret.as_bytes());
    let mut wrap_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut wrap_key)
        .expect("32-byte output is valid for HKDF-SHA-256");

    // 4. ChaCha20-Poly1305 decrypt the file key
    let cipher = ChaCha20Poly1305::new((&wrap_key).into());
    let nonce = Nonce::from(ZERO_NONCE);
    let file_key_bytes = cipher
        .decrypt(&nonce, encrypted_file_key)
        .map_err(|_| anyhow::anyhow!("AEAD decryption failed — wrong key or tampered data"))?;

    // Zeroize the wrap key
    wrap_key.zeroize();

    let file_key: [u8; 16] = file_key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("decrypted file key is not 16 bytes"))?;

    Ok(file_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use lupine_kem::hybrid::generate_keypair;
    use ml_kem::MlKem768;

    #[test]
    fn wrap_unwrap_round_trip() {
        let (sk, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
        let file_key: [u8; 16] = [0x42; 16];

        let (ct_bytes, encrypted) = wrap_file_key(&file_key, &pk).expect("wrap");
        let recovered = unwrap_file_key(&ct_bytes, &encrypted, &sk).expect("unwrap");

        assert_eq!(file_key, recovered, "file key round-trip failed");
    }

    #[test]
    fn wrap_unwrap_random_file_key() {
        let (sk, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
        let mut file_key = [0u8; 16];
        rand::RngCore::fill_bytes(&mut OsRng, &mut file_key);

        let (ct_bytes, encrypted) = wrap_file_key(&file_key, &pk).expect("wrap");
        let recovered = unwrap_file_key(&ct_bytes, &encrypted, &sk).expect("unwrap");

        assert_eq!(file_key, recovered, "random file key round-trip failed");
    }

    #[test]
    fn unwrap_wrong_key_fails() {
        let (_, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
        let (wrong_sk, _) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen2");
        let file_key: [u8; 16] = [0xAB; 16];

        let (ct_bytes, encrypted) = wrap_file_key(&file_key, &pk).expect("wrap");
        let result = unwrap_file_key(&ct_bytes, &encrypted, &wrong_sk);

        assert!(result.is_err(), "unwrap with wrong key must fail");
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let (sk, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
        let file_key: [u8; 16] = [0xCD; 16];

        let (ct_bytes, mut encrypted) = wrap_file_key(&file_key, &pk).expect("wrap");
        // Tamper with the encrypted file key
        encrypted[0] ^= 0xFF;
        let result = unwrap_file_key(&ct_bytes, &encrypted, &sk);

        assert!(result.is_err(), "tampered encrypted file key must fail");
    }

    #[test]
    fn encrypted_file_key_length() {
        let (_, pk) = generate_keypair::<MlKem768>(&mut OsRng).expect("keygen");
        let file_key: [u8; 16] = [0x00; 16];

        let (ct_bytes, encrypted) = wrap_file_key(&file_key, &pk).expect("wrap");

        // KEM ciphertext: 32 (x25519 ephem pk) + 1088 (ML-KEM-768 ct) = 1120
        assert_eq!(ct_bytes.len(), 1120, "KEM ciphertext should be 1120 bytes");
        // Encrypted file key: 16 (plaintext) + 16 (Poly1305 tag) = 32
        assert_eq!(encrypted.len(), 32, "encrypted file key should be 32 bytes");
    }
}
