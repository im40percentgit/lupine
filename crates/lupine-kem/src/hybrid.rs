//! Hybrid KEM: X25519 + ML-KEM with KitchenSink combiner (Phase 3).
//!
//! Combines classical X25519 Diffie-Hellman with post-quantum ML-KEM so that
//! security holds as long as *at least one* component is unbroken. The shared
//! secret is derived via [`crate::combiner::kitchen_sink`] (HKDF-SHA-256 over
//! all secrets, ciphertexts, and public keys).
//!
//! # Protocol summary
//!
//! **Key generation:** generate independent X25519 and ML-KEM keypairs.
//!
//! **Encapsulation (sender):**
//! 1. Generate a fresh X25519 ephemeral secret; compute `x25519_ct = ephem_pk`.
//! 2. Perform `x25519_ss = ECDH(ephem_sk, static_pk)`.
//! 3. Encapsulate to the ML-KEM public key: `(mlkem_ct, mlkem_ss)`.
//! 4. Combine: `shared = KitchenSink(x25519_ss, mlkem_ss, x25519_ct, mlkem_ct, x25519_pk, mlkem_pk)`.
//!
//! **Decapsulation (receiver):**
//! 1. Recover `x25519_ss = ECDH(static_sk, ephem_pk)` (= `x25519_ct`).
//! 2. Decapsulate ML-KEM: `mlkem_ss`.
//! 3. Combine identically → same `shared`.
//!
//! @decision DEC-HYBRID-KEM-002
//! @title X25519 ephemeral public as "ciphertext" component
//! @status accepted
//! @rationale In a hybrid KEM the X25519 "ciphertext" is the sender's ephemeral
//!   public key: the receiver recovers the same DH shared secret by computing
//!   ECDH(static_sk, ephem_pk). Including the ephemeral public key in the
//!   KitchenSink IKM binds it to the combined secret, preventing key-substitution
//!   attacks. The composite ciphertext type stores it as a 32-byte field alongside
//!   the ML-KEM ciphertext.
//!
//! @decision DEC-HYBRID-KEM-003
//! @title Generic over ML-KEM parameter set
//! @status accepted
//! @rationale Following the same `<P: KemCore>` pattern from `mlkem.rs` lets
//!   all three ML-KEM parameter sets (512/768/1024) share a single hybrid
//!   implementation. Type aliases `HybridKem512` etc. give callers ergonomic
//!   concrete types without any runtime overhead.

extern crate alloc;

use alloc::vec::Vec;

use ml_kem::{
    EncodedSizeUser, KemCore,
    kem::{Decapsulate, Encapsulate},
};
use rand_core::CryptoRngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroize;

use lupine_core::{Error, Result, SharedSecret};

use crate::combiner::kitchen_sink;
use crate::mlkem::{MlKemCiphertext, MlKemPublicKey, MlKemSecretKey};

// ── Type aliases ─────────────────────────────────────────────────────────────

/// Hybrid (X25519 + ML-KEM-512) public key.
pub type HybridKemPublicKey512 = HybridKemPublicKey<ml_kem::MlKem512>;
/// Hybrid (X25519 + ML-KEM-512) secret key.
pub type HybridKemSecretKey512 = HybridKemSecretKey<ml_kem::MlKem512>;
/// Hybrid (X25519 + ML-KEM-512) ciphertext.
pub type HybridKemCiphertext512 = HybridKemCiphertext<ml_kem::MlKem512>;

/// Hybrid (X25519 + ML-KEM-768) public key.
pub type HybridKemPublicKey768 = HybridKemPublicKey<ml_kem::MlKem768>;
/// Hybrid (X25519 + ML-KEM-768) secret key.
pub type HybridKemSecretKey768 = HybridKemSecretKey<ml_kem::MlKem768>;
/// Hybrid (X25519 + ML-KEM-768) ciphertext.
pub type HybridKemCiphertext768 = HybridKemCiphertext<ml_kem::MlKem768>;

/// Hybrid (X25519 + ML-KEM-1024) public key.
pub type HybridKemPublicKey1024 = HybridKemPublicKey<ml_kem::MlKem1024>;
/// Hybrid (X25519 + ML-KEM-1024) secret key.
pub type HybridKemSecretKey1024 = HybridKemSecretKey<ml_kem::MlKem1024>;
/// Hybrid (X25519 + ML-KEM-1024) ciphertext.
pub type HybridKemCiphertext1024 = HybridKemCiphertext<ml_kem::MlKem1024>;

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate a hybrid X25519 + ML-KEM keypair for parameter set `P`.
///
/// Returns `(secret_key, public_key)`.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if the RNG fails.
pub fn generate_keypair<P>(
    rng: &mut impl CryptoRngCore,
) -> Result<(HybridKemSecretKey<P>, HybridKemPublicKey<P>)>
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser,
{
    // X25519 component.
    let x_sk = X25519StaticSecret::random_from_rng(&mut *rng);
    let x_pk = X25519PublicKey::from(&x_sk);

    // ML-KEM component.
    let (mlkem_sk, mlkem_pk) = crate::mlkem::generate_keypair::<P>(rng)?;

    let pk = HybridKemPublicKey {
        x25519_pk: x_pk,
        mlkem_pk,
    };
    let sk = HybridKemSecretKey {
        x25519_sk: x_sk,
        x25519_pk: pk.x25519_pk,
        mlkem_sk,
        mlkem_pk_bytes: pk.mlkem_pk.to_bytes().to_vec(),
    };
    Ok((sk, pk))
}

// ── HybridKemPublicKey ────────────────────────────────────────────────────────

/// A hybrid X25519 + ML-KEM encapsulation (public) key.
///
/// Use the type aliases [`HybridKemPublicKey512`], [`HybridKemPublicKey768`],
/// or [`HybridKemPublicKey1024`] for concrete parameter sets.
pub struct HybridKemPublicKey<P: KemCore> {
    /// X25519 static public key (32 bytes).
    x25519_pk: X25519PublicKey,
    /// ML-KEM encapsulation key.
    mlkem_pk: MlKemPublicKey<P>,
}

impl<P> HybridKemPublicKey<P>
where
    P: KemCore,
    P::EncapsulationKey: EncodedSizeUser,
{
    /// Deserialize a hybrid public key from bytes.
    ///
    /// Format: 32 bytes X25519 public key || ML-KEM public key bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the byte slice is too short or the
    /// ML-KEM portion is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            return Err(Error::InvalidKey);
        }
        let x_bytes: [u8; 32] = bytes[..32].try_into().map_err(|_| Error::InvalidKey)?;
        let x25519_pk = X25519PublicKey::from(x_bytes);
        let mlkem_pk = MlKemPublicKey::<P>::from_bytes(&bytes[32..])?;
        Ok(Self { x25519_pk, mlkem_pk })
    }

    /// Serialize this hybrid public key to bytes.
    ///
    /// Format: 32 bytes X25519 public key || ML-KEM public key bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.mlkem_pk.to_bytes().len());
        out.extend_from_slice(self.x25519_pk.as_bytes());
        out.extend_from_slice(self.mlkem_pk.to_bytes());
        out
    }

    /// Encapsulate a fresh shared secret to this hybrid public key.
    ///
    /// Returns `(ciphertext, shared_secret)`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encapsulation`] on RNG failure or ML-KEM failure.
    pub fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(HybridKemCiphertext<P>, SharedSecret)>
    where
        P::EncapsulationKey: Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    {
        // X25519: generate ephemeral keypair and perform DH.
        let ephem_sk = X25519StaticSecret::random_from_rng(&mut *rng);
        let ephem_pk = X25519PublicKey::from(&ephem_sk);
        let x25519_ss = ephem_sk.diffie_hellman(&self.x25519_pk);

        // ML-KEM: encapsulate.
        let (mlkem_ct, mlkem_ss) = self.mlkem_pk.encapsulate(rng)?;

        // KitchenSink combine.
        let combined = kitchen_sink(
            x25519_ss.as_bytes(),
            mlkem_ss.as_bytes(),
            ephem_pk.as_bytes(),          // x25519 "ciphertext" = ephemeral pk
            mlkem_ct.to_bytes(),
            self.x25519_pk.as_bytes(),
            self.mlkem_pk.to_bytes(),
        );

        let ct = HybridKemCiphertext {
            x25519_ephem_pk: ephem_pk,
            mlkem_ct,
        };
        Ok((ct, combined))
    }
}

// ── HybridKemSecretKey ────────────────────────────────────────────────────────

/// A hybrid X25519 + ML-KEM decapsulation (secret) key.
///
/// Use the type aliases [`HybridKemSecretKey512`], [`HybridKemSecretKey768`],
/// or [`HybridKemSecretKey1024`] for concrete parameter sets.
///
/// # Memory safety
///
/// `Drop` zeroizes `mlkem_pk_bytes` (the cached public key byte cache, which
/// is non-secret but cleared for defense in depth). `x25519_sk`
/// (`StaticSecret`) already implements `Zeroize` and zeroizes itself on drop.
/// `mlkem_sk` (`MlKemSecretKey`) has its own `Drop` impl that zeroizes its
/// inner byte fields and delegates to the native key's `ZeroizeOnDrop`.
pub struct HybridKemSecretKey<P: KemCore> {
    /// X25519 static secret key.
    x25519_sk: X25519StaticSecret,
    /// X25519 static public key (cached for KitchenSink input).
    x25519_pk: X25519PublicKey,
    /// ML-KEM decapsulation key.
    mlkem_sk: MlKemSecretKey<P>,
    /// Cached ML-KEM public key bytes (for KitchenSink input).
    mlkem_pk_bytes: Vec<u8>,
}

impl<P: KemCore> Drop for HybridKemSecretKey<P> {
    fn drop(&mut self) {
        // mlkem_pk_bytes is non-secret public key material, but we zeroize
        // it defensively to eliminate all key-related bytes from this struct.
        self.mlkem_pk_bytes.zeroize();
        // x25519_sk: StaticSecret implements Zeroize/ZeroizeOnDrop natively.
        // mlkem_sk: has its own Drop impl (see MlKemSecretKey).
    }
}

impl<P> HybridKemSecretKey<P>
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser,
{
    /// Serialize this hybrid secret key to bytes.
    ///
    /// Format: 32 bytes X25519 secret || 32 bytes X25519 public || ML-KEM secret bytes.
    ///
    /// Treat the result as secret material.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mlkem_sk_bytes = self.mlkem_sk.to_bytes();
        let mut out = Vec::with_capacity(32 + 32 + mlkem_sk_bytes.len());
        out.extend_from_slice(self.x25519_sk.as_bytes());
        out.extend_from_slice(self.x25519_pk.as_bytes());
        out.extend_from_slice(mlkem_sk_bytes);
        out
    }

    /// Deserialize a hybrid secret key from bytes.
    ///
    /// Format: 32 bytes X25519 secret || 32 bytes X25519 public || ML-KEM secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the bytes are too short or the ML-KEM
    /// portion is malformed.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 64 {
            return Err(Error::InvalidKey);
        }
        let x_sk_bytes: [u8; 32] = bytes[..32].try_into().map_err(|_| Error::InvalidKey)?;
        let x_pk_bytes: [u8; 32] = bytes[32..64].try_into().map_err(|_| Error::InvalidKey)?;
        let x25519_sk = X25519StaticSecret::from(x_sk_bytes);
        let x25519_pk = X25519PublicKey::from(x_pk_bytes);
        let mlkem_sk = MlKemSecretKey::<P>::from_bytes(&bytes[64..])?;
        // mlkem_pk_bytes unavailable after deserialization — leave empty.
        // Decapsulation does not need the public key bytes in normal usage;
        // they are only required when combining via KitchenSink. The caller
        // must supply a HybridKemCiphertext that was encapsulated to the
        // matching public key (same requirement as plain ML-KEM).
        Ok(Self {
            x25519_sk,
            x25519_pk,
            mlkem_sk,
            mlkem_pk_bytes: Vec::new(),
        })
    }

    /// Set the cached ML-KEM public key bytes.
    ///
    /// This is set automatically by [`generate_keypair`]. If the key was
    /// deserialized via [`Self::from_bytes`], the caller can restore the cached
    /// bytes by calling this method with the corresponding public key bytes.
    pub fn set_mlkem_pk_bytes(&mut self, pk_bytes: Vec<u8>) {
        self.mlkem_pk_bytes = pk_bytes;
    }

    /// Decapsulate a hybrid ciphertext and return the combined shared secret.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decapsulation`] if the ML-KEM decapsulation fails.
    /// Returns [`Error::InvalidKey`] if the ML-KEM public key bytes are missing
    /// (the key was deserialized without calling [`Self::set_mlkem_pk_bytes`]).
    pub fn decapsulate(
        &self,
        ct: &HybridKemCiphertext<P>,
    ) -> Result<SharedSecret>
    where
        P::DecapsulationKey: Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
    {
        if self.mlkem_pk_bytes.is_empty() {
            return Err(Error::InvalidKey);
        }

        // X25519: recover shared secret using our static key and the ephemeral pk.
        let x25519_ss = self.x25519_sk.diffie_hellman(&ct.x25519_ephem_pk);

        // ML-KEM: decapsulate.
        let mlkem_ss = self.mlkem_sk.decapsulate(&ct.mlkem_ct)?;

        // KitchenSink combine — must use identical inputs as encapsulation.
        let combined = kitchen_sink(
            x25519_ss.as_bytes(),
            mlkem_ss.as_bytes(),
            ct.x25519_ephem_pk.as_bytes(),   // x25519 "ciphertext"
            ct.mlkem_ct.to_bytes(),
            self.x25519_pk.as_bytes(),
            &self.mlkem_pk_bytes,
        );

        Ok(combined)
    }
}

// ── HybridKemCiphertext ───────────────────────────────────────────────────────

/// A hybrid X25519 + ML-KEM ciphertext.
pub struct HybridKemCiphertext<P: KemCore> {
    /// X25519 ephemeral public key (the DH "ciphertext").
    x25519_ephem_pk: X25519PublicKey,
    /// ML-KEM ciphertext.
    mlkem_ct: MlKemCiphertext<P>,
}

impl<P: KemCore> HybridKemCiphertext<P> {
    /// Serialize this hybrid ciphertext to bytes.
    ///
    /// Format: 32 bytes X25519 ephemeral public key || ML-KEM ciphertext bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mlkem_bytes = self.mlkem_ct.to_bytes();
        let mut out = Vec::with_capacity(32 + mlkem_bytes.len());
        out.extend_from_slice(self.x25519_ephem_pk.as_bytes());
        out.extend_from_slice(mlkem_bytes);
        out
    }

    /// Deserialize a hybrid ciphertext from bytes.
    ///
    /// Format: 32 bytes X25519 ephemeral public key || ML-KEM ciphertext bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decapsulation`] if the byte slice is too short.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < 32 {
            return Err(Error::Decapsulation);
        }
        let x_bytes: [u8; 32] = bytes[..32].try_into().map_err(|_| Error::Decapsulation)?;
        let x25519_ephem_pk = X25519PublicKey::from(x_bytes);
        let mlkem_ct = MlKemCiphertext::<P>::from_bytes(&bytes[32..]);
        Ok(Self { x25519_ephem_pk, mlkem_ct })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    // Helper: full hybrid KEM round-trip for parameter set P.
    fn round_trip<P>()
    where
        P: KemCore,
        P::DecapsulationKey: EncodedSizeUser
            + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        P::EncapsulationKey: EncodedSizeUser
            + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
    {
        let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen failed");
        let (ct, ss_send) = pk.encapsulate(&mut OsRng).expect("encapsulate failed");
        let ss_recv = sk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(
            ss_send.as_bytes(),
            ss_recv.as_bytes(),
            "hybrid shared secrets must match"
        );
    }

    #[test]
    fn round_trip_512() { round_trip::<ml_kem::MlKem512>(); }
    #[test]
    fn round_trip_768() { round_trip::<ml_kem::MlKem768>(); }
    #[test]
    fn round_trip_1024() { round_trip::<ml_kem::MlKem1024>(); }

    // Tamper detection: modifying the ML-KEM ciphertext bytes changes the
    // combined secret. (ML-KEM implicit rejection ensures decapsulation still
    // succeeds but produces a different mlkem_ss, which flows through KitchenSink.)
    fn tamper_detection<P>()
    where
        P: KemCore,
        P::DecapsulationKey: EncodedSizeUser
            + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        P::EncapsulationKey: EncodedSizeUser
            + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
    {
        let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen failed");
        let (ct, ss_good) = pk.encapsulate(&mut OsRng).expect("encapsulate failed");

        // Tamper with the ML-KEM part of the ciphertext (bytes 32+).
        let mut ct_bytes = ct.to_bytes();
        ct_bytes[32] ^= 0xFF;
        let ct_tampered = HybridKemCiphertext::<P>::from_bytes(&ct_bytes)
            .expect("from_bytes must succeed even for tampered ciphertext");

        let ss_bad = sk.decapsulate(&ct_tampered).expect("decapsulate must succeed (implicit rejection)");
        assert_ne!(
            ss_good.as_bytes(),
            ss_bad.as_bytes(),
            "tampered ciphertext must yield a different combined secret"
        );
    }

    #[test]
    fn tamper_detection_512() { tamper_detection::<ml_kem::MlKem512>(); }
    #[test]
    fn tamper_detection_768() { tamper_detection::<ml_kem::MlKem768>(); }
    #[test]
    fn tamper_detection_1024() { tamper_detection::<ml_kem::MlKem1024>(); }

    // Combined secret must be exactly 32 bytes.
    #[test]
    fn shared_secret_length() {
        let (sk, pk) = generate_keypair::<ml_kem::MlKem768>(&mut OsRng).expect("keygen failed");
        let (ct, ss) = pk.encapsulate(&mut OsRng).expect("encapsulate failed");
        assert_eq!(ss.as_bytes().len(), 32, "combined shared secret must be 32 bytes");
        let ss2 = sk.decapsulate(&ct).expect("decapsulate failed");
        assert_eq!(ss2.as_bytes().len(), 32);
    }

    // Key serialization round-trip.
    fn key_serialization<P>()
    where
        P: KemCore,
        P::DecapsulationKey: EncodedSizeUser
            + Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        P::EncapsulationKey: EncodedSizeUser
            + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
    {
        let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen failed");

        // Public key round-trip.
        let pk_bytes = pk.to_bytes();
        let pk2 = HybridKemPublicKey::<P>::from_bytes(&pk_bytes).expect("pk from_bytes failed");
        assert_eq!(pk.to_bytes(), pk2.to_bytes(), "pk round-trip failed");

        // Secret key round-trip.
        let sk_bytes = sk.to_bytes();
        let mut sk2 = HybridKemSecretKey::<P>::from_bytes(&sk_bytes).expect("sk from_bytes failed");
        // Restore pk bytes so decapsulation works.
        sk2.set_mlkem_pk_bytes(pk.mlkem_pk.to_bytes().to_vec());

        // Both secret keys must produce the same shared secret.
        let (ct, ss1) = pk.encapsulate(&mut OsRng).expect("encapsulate failed");
        let ss2 = sk2.decapsulate(&ct).expect("decapsulate with deserialized sk failed");
        assert_eq!(ss1.as_bytes(), ss2.as_bytes(), "deserialized sk must produce same shared secret");
    }

    #[test]
    fn key_serialization_512() { key_serialization::<ml_kem::MlKem512>(); }
    #[test]
    fn key_serialization_768() { key_serialization::<ml_kem::MlKem768>(); }
    #[test]
    fn key_serialization_1024() { key_serialization::<ml_kem::MlKem1024>(); }
}
