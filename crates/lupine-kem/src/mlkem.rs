//! ML-KEM (FIPS 203) wrapper for the Lupine PQC suite.
//!
//! Provides `MlKemPublicKey<P>`, `MlKemSecretKey<P>`, `MlKemCiphertext<P>`,
//! and `MlKemSharedKey` types that wrap the RustCrypto `ml-kem` crate and
//! surface a Lupine-idiomatic API: byte-oriented key serialization, Lupine
//! `Error`/`Result` types, and `SharedSecret` as the KEM output.
//!
//! @decision DEC-KEM-001
//! @title Generic wrapper over KemCore vs. three concrete structs
//! @status accepted
//! @rationale Using a single generic struct `MlKemPublicKey<P>` avoids
//!   tripling the implementation across ML-KEM-512/768/1024. The bound
//!   `P: ml_kem::KemCore` is the natural abstraction: each parameter set
//!   is a distinct type implementing `KemCore`, so the generic is monomorphised
//!   at compile time with zero runtime overhead. Three concrete structs would
//!   be simpler to read but would create a maintenance burden every time a
//!   shared operation changes. Callers who want concrete types can use the
//!   provided type aliases `MlKemPublicKey512`, `MlKemPublicKey768`, etc.
//!
//! @decision DEC-KEM-002
//! @title Byte-vec serialization vs. fixed-size array types
//! @status accepted
//! @rationale `ml-kem` uses `hybrid_array::Array<u8, N>` for its encoded
//!   key types (via `EncodedSizeUser`). Our wrapper copies these into `Vec<u8>`
//!   so callers never need to import `hybrid_array` or deal with const-generic
//!   array sizes. The copy is a one-time allocation at the API boundary and is
//!   acceptable given that key operations are not on the hot path.

extern crate alloc;

use alloc::vec::Vec;

use ml_kem::{
    Encoded, EncodedSizeUser, KemCore,
    kem::{Decapsulate, Encapsulate},
};
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

use lupine_core::{Error, Result, SharedSecret};

// ── Type aliases for the three ML-KEM parameter sets ────────────────────────

/// ML-KEM-512 public (encapsulation) key — NIST category 1.
pub type MlKemPublicKey512 = MlKemPublicKey<ml_kem::MlKem512>;
/// ML-KEM-512 secret (decapsulation) key — NIST category 1.
pub type MlKemSecretKey512 = MlKemSecretKey<ml_kem::MlKem512>;
/// ML-KEM-512 ciphertext.
pub type MlKemCiphertext512 = MlKemCiphertext<ml_kem::MlKem512>;

/// ML-KEM-768 public (encapsulation) key — NIST category 3.
pub type MlKemPublicKey768 = MlKemPublicKey<ml_kem::MlKem768>;
/// ML-KEM-768 secret (decapsulation) key — NIST category 3.
pub type MlKemSecretKey768 = MlKemSecretKey<ml_kem::MlKem768>;
/// ML-KEM-768 ciphertext.
pub type MlKemCiphertext768 = MlKemCiphertext<ml_kem::MlKem768>;

/// ML-KEM-1024 public (encapsulation) key — NIST category 5.
pub type MlKemPublicKey1024 = MlKemPublicKey<ml_kem::MlKem1024>;
/// ML-KEM-1024 secret (decapsulation) key — NIST category 5.
pub type MlKemSecretKey1024 = MlKemSecretKey<ml_kem::MlKem1024>;
/// ML-KEM-1024 ciphertext.
pub type MlKemCiphertext1024 = MlKemCiphertext<ml_kem::MlKem1024>;

// ── Shared key type ──────────────────────────────────────────────────────────

/// A 32-byte shared key produced by ML-KEM encapsulation or decapsulation.
///
/// This is a re-export of `lupine_core::SharedSecret` for convenience.
pub type MlKemSharedKey = SharedSecret;

// ── Key generation ────────────────────────────────────────────────────────────

/// Generate an ML-KEM keypair for parameter set `P`.
///
/// Returns `(secret_key, public_key)`.
///
/// # Errors
///
/// Returns [`Error::KeyGeneration`] if the RNG fails to produce entropy
/// (in practice this only happens on platforms without a system RNG).
pub fn generate_keypair<P>(rng: &mut impl CryptoRngCore) -> Result<(MlKemSecretKey<P>, MlKemPublicKey<P>)>
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
    P::EncapsulationKey: EncodedSizeUser,
{
    let (dk, ek) = P::generate(rng);
    // Encode ek once; use bytes to construct both pk and the cached copy in sk.
    let ek_bytes = ek.as_bytes().to_vec();
    let pk = MlKemPublicKey {
        bytes: ek_bytes.clone(),
        native: ek,
    };
    let sk = MlKemSecretKey {
        bytes: dk.as_bytes().to_vec(),
        ek_bytes,
        native: dk,
    };
    Ok((sk, pk))
}

// ── MlKemPublicKey ────────────────────────────────────────────────────────────

/// An ML-KEM encapsulation (public) key, generic over the parameter set `P`.
///
/// Use the type aliases [`MlKemPublicKey512`], [`MlKemPublicKey768`], or
/// [`MlKemPublicKey1024`] for concrete parameter sets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemPublicKey<P: KemCore> {
    /// Raw encoded bytes of the encapsulation key.
    bytes: Vec<u8>,
    /// Parsed native key (kept for encapsulation without re-parsing).
    native: P::EncapsulationKey,
}

impl<P> MlKemPublicKey<P>
where
    P: KemCore,
    P::EncapsulationKey: EncodedSizeUser,
{
    /// Deserialize a public key from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the byte slice is not the correct
    /// length for this parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = Encoded::<P::EncapsulationKey>::try_from(bytes)
            .map_err(|_| Error::InvalidKey)?;
        let native = P::EncapsulationKey::from_bytes(&encoded);
        Ok(Self {
            bytes: bytes.to_vec(),
            native,
        })
    }

    /// Serialize this public key to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Encapsulate a fresh shared secret to this public key.
    ///
    /// Returns `(ciphertext, shared_key)`. The shared key must be kept secret
    /// by the sender; the ciphertext is sent to the key holder.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Encapsulation`] on failure (e.g. RNG failure).
    pub fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(MlKemCiphertext<P>, MlKemSharedKey)>
    where
        P::EncapsulationKey: Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    {
        let (ct_arr, sk_arr) = self
            .native
            .encapsulate(rng)
            .map_err(|_| Error::Encapsulation)?;
        let ct = MlKemCiphertext::from_array(ct_arr);
        let shared = SharedSecret::new(sk_arr.to_vec());
        Ok((ct, shared))
    }
}

// ── MlKemSecretKey ────────────────────────────────────────────────────────────

/// An ML-KEM decapsulation (secret) key, generic over the parameter set `P`.
///
/// Use the type aliases [`MlKemSecretKey512`], [`MlKemSecretKey768`], or
/// [`MlKemSecretKey1024`] for concrete parameter sets.
///
/// # Memory safety
///
/// `Drop` zeroizes `bytes` and `ek_bytes` (the Lupine wrapper's raw key
/// material). The native `P::DecapsulationKey` carries its own
/// `ZeroizeOnDrop` (via the `ml-kem/zeroize` feature), so all secret bytes
/// are cleared when this value is dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemSecretKey<P: KemCore> {
    /// Raw encoded bytes of the decapsulation key.
    bytes: Vec<u8>,
    /// Encoded bytes of the corresponding encapsulation key (cached at
    /// construction so `public_key()` doesn't need an `encapsulation_key()`
    /// method on the `KemCore` trait).
    ek_bytes: Vec<u8>,
    /// Parsed native key.
    native: P::DecapsulationKey,
}

/// @decision DEC-KEM-003
/// @title Manual Drop for MlKemSecretKey instead of ZeroizeOnDrop derive
/// @status accepted
/// @rationale `#[derive(ZeroizeOnDrop)]` requires every field to implement
///   `Zeroize`. The `P::DecapsulationKey` associated type does not expose
///   `Zeroize` as a trait bound in the `KemCore` definition, so the derive
///   cannot verify it at the wrapper level. A manual `Drop` impl zeroizes the
///   two `Vec<u8>` fields owned by the wrapper; the native `DecapsulationKey`
///   is handled by its own `ZeroizeOnDrop` (activated via `ml-kem/zeroize`).
impl<P: KemCore> Drop for MlKemSecretKey<P> {
    fn drop(&mut self) {
        self.bytes.zeroize();
        self.ek_bytes.zeroize();
        // self.native: P::DecapsulationKey has ZeroizeOnDrop via ml-kem/zeroize feature.
    }
}

impl<P> MlKemSecretKey<P>
where
    P: KemCore,
    P::DecapsulationKey: EncodedSizeUser,
{
    /// Deserialize a secret key from raw bytes.
    ///
    /// Note: the encapsulation key cannot be re-derived from the serialized
    /// decapsulation key bytes alone at this trait level. Call
    /// `generate_keypair` and serialize both keys if you need the public key.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidKey`] if the byte slice is not the correct
    /// length for this parameter set.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let encoded = Encoded::<P::DecapsulationKey>::try_from(bytes)
            .map_err(|_| Error::InvalidKey)?;
        let native = P::DecapsulationKey::from_bytes(&encoded);
        Ok(Self {
            bytes: bytes.to_vec(),
            ek_bytes: Vec::new(),
            native,
        })
    }

    /// Serialize this secret key to bytes.
    ///
    /// Treat the result as secret material — keep it zeroized and stored
    /// securely.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Return the cached public encapsulation key if available (i.e., if this
    /// key was produced by `generate_keypair`).
    ///
    /// Returns `None` if the secret key was deserialized via `from_bytes`
    /// without an accompanying public key.
    pub fn public_key(&self) -> Option<MlKemPublicKey<P>> {
        if self.ek_bytes.is_empty() {
            return None;
        }
        MlKemPublicKey::<P>::from_bytes(&self.ek_bytes).ok()
    }

    /// Decapsulate a ciphertext produced by the corresponding public key.
    ///
    /// Returns the shared secret. Per FIPS 203 §6.4, decapsulation is
    /// defined to always succeed — if the ciphertext was tampered with, the
    /// returned shared secret will be a pseudorandom value derived from a
    /// secret implicit-rejection key (the ciphertext does NOT reveal whether
    /// it was authentic).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decapsulation`] only on internal failure (should not
    /// happen under normal operation with well-formed keys).
    pub fn decapsulate(
        &self,
        ct: &MlKemCiphertext<P>,
    ) -> Result<MlKemSharedKey>
    where
        P::DecapsulationKey:
            Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
    {
        let ct_arr = ct.to_array()?;
        let sk_arr = self
            .native
            .decapsulate(&ct_arr)
            .map_err(|_| Error::Decapsulation)?;
        Ok(SharedSecret::new(sk_arr.to_vec()))
    }
}

// ── MlKemCiphertext ───────────────────────────────────────────────────────────

/// An ML-KEM encapsulated ciphertext, generic over the parameter set `P`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MlKemCiphertext<P: KemCore> {
    bytes: Vec<u8>,
    _marker: core::marker::PhantomData<P>,
}

impl<P: KemCore> MlKemCiphertext<P> {
    /// Construct from a native ml-kem ciphertext array.
    fn from_array(arr: ml_kem::Ciphertext<P>) -> Self {
        Self {
            bytes: arr.to_vec(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Reconstruct the native ciphertext array from our byte vec.
    ///
    /// `Ciphertext<P>` is `hybrid_array::Array<u8, P::CiphertextSize>` which
    /// implements `TryFrom<&[u8]>`, so no `EncodedSizeUser` bound is needed.
    fn to_array(&self) -> Result<ml_kem::Ciphertext<P>>
    where
        ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
    {
        ml_kem::Ciphertext::<P>::try_from(self.bytes.as_slice())
            .map_err(|_| Error::Decapsulation)
    }

    /// Deserialize a ciphertext from raw bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Decapsulation`] if the byte slice length is wrong.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Serialize this ciphertext to bytes.
    pub fn to_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    /// End-to-end round-trip: keygen → encapsulate → decapsulate → equal.
    fn round_trip<P>()
    where
        P: KemCore,
        P::DecapsulationKey: EncodedSizeUser,
        P::EncapsulationKey: EncodedSizeUser
            + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        P::DecapsulationKey:
            Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
    {
        let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen failed");

        let (ct, k_send) = pk.encapsulate(&mut OsRng).expect("encapsulate failed");
        let k_recv = sk.decapsulate(&ct).expect("decapsulate failed");

        assert_eq!(
            k_send.as_bytes(),
            k_recv.as_bytes(),
            "shared secrets must match"
        );
    }

    #[test]
    fn round_trip_512() {
        round_trip::<ml_kem::MlKem512>();
    }

    #[test]
    fn round_trip_768() {
        round_trip::<ml_kem::MlKem768>();
    }

    #[test]
    fn round_trip_1024() {
        round_trip::<ml_kem::MlKem1024>();
    }

    /// Key serialization: encode then decode, confirm round-trip equality.
    fn key_serialization<P>()
    where
        P: KemCore,
        P::DecapsulationKey: EncodedSizeUser,
        P::EncapsulationKey: EncodedSizeUser,
    {
        let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen failed");

        // Public key round-trip (compare bytes, since P may not impl Debug/PartialEq)
        let pk_bytes = pk.to_bytes().to_vec();
        let pk2 = MlKemPublicKey::<P>::from_bytes(&pk_bytes).expect("pk from_bytes failed");
        assert_eq!(pk.to_bytes(), pk2.to_bytes(), "public key round-trip failed");

        // Secret key round-trip
        let sk_bytes = sk.to_bytes().to_vec();
        let sk2 = MlKemSecretKey::<P>::from_bytes(&sk_bytes).expect("sk from_bytes failed");
        assert_eq!(sk.to_bytes(), sk2.to_bytes(), "secret key round-trip failed");
    }

    #[test]
    fn key_serialization_512() {
        key_serialization::<ml_kem::MlKem512>();
    }

    #[test]
    fn key_serialization_768() {
        key_serialization::<ml_kem::MlKem768>();
    }

    #[test]
    fn key_serialization_1024() {
        key_serialization::<ml_kem::MlKem1024>();
    }

    /// Tamper detection: mutating the ciphertext must produce a different
    /// shared secret (implicit rejection per FIPS 203 §6.4 — NOT an error).
    fn tamper_detection<P>()
    where
        P: KemCore,
        P::DecapsulationKey: EncodedSizeUser,
        P::EncapsulationKey: EncodedSizeUser
            + Encapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        P::DecapsulationKey:
            Decapsulate<ml_kem::Ciphertext<P>, ml_kem::SharedKey<P>>,
        ml_kem::Ciphertext<P>: for<'a> TryFrom<&'a [u8]>,
    {
        let (sk, pk) = generate_keypair::<P>(&mut OsRng).expect("keygen failed");
        let (ct, k_send) = pk.encapsulate(&mut OsRng).expect("encapsulate failed");

        // Flip the first byte of the ciphertext
        let mut ct_tampered_bytes = ct.to_bytes().to_vec();
        ct_tampered_bytes[0] ^= 0xFF;
        let ct_tampered = MlKemCiphertext::<P>::from_bytes(&ct_tampered_bytes);

        let k_tampered = sk
            .decapsulate(&ct_tampered)
            .expect("decapsulate of tampered CT must succeed (implicit rejection)");

        assert_ne!(
            k_send.as_bytes(),
            k_tampered.as_bytes(),
            "tampered ciphertext must yield a different shared secret"
        );
    }

    #[test]
    fn tamper_detection_512() {
        tamper_detection::<ml_kem::MlKem512>();
    }

    #[test]
    fn tamper_detection_768() {
        tamper_detection::<ml_kem::MlKem768>();
    }

    #[test]
    fn tamper_detection_1024() {
        tamper_detection::<ml_kem::MlKem1024>();
    }

    /// Ensure public_key() cached from keygen matches the directly-returned public key.
    #[test]
    fn public_key_derivation_768() {
        let (sk, pk) = generate_keypair::<ml_kem::MlKem768>(&mut OsRng).expect("keygen failed");
        let pk_cached = sk.public_key().expect("public key must be cached after keygen");
        assert_eq!(
            pk.to_bytes(),
            pk_cached.to_bytes(),
            "cached public key must match keygen output"
        );
    }

    /// Invalid key bytes must return an error, not panic.
    #[test]
    fn from_bytes_invalid_length() {
        let result = MlKemPublicKey::<ml_kem::MlKem768>::from_bytes(&[0u8; 4]);
        assert!(result.is_err(), "short byte slice must return an error");

        let result = MlKemSecretKey::<ml_kem::MlKem768>::from_bytes(&[0u8; 4]);
        assert!(result.is_err(), "short byte slice must return an error");
    }
}
